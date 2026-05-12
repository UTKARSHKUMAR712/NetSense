#include "traffic_db.h"
#include "../third_party/sqlite/sqlite3.h"
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <iostream>
#include <condition_variable>

namespace TrafficDB {

    struct WriteTask {
        int sessionId;
        ProxyFlow flow;
    };

    static sqlite3* g_db = nullptr;
    static std::mutex g_dbMutex;
    static std::thread g_workerThread;
    static std::atomic<bool> g_running{false};
    static std::queue<WriteTask> g_writeQueue;
    static std::mutex g_queueMutex;
    static std::condition_variable g_queueCond;

    static void ExecuteSQL(const char* sql) {
        char* err = nullptr;
        if (sqlite3_exec(g_db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
            std::cerr << "SQLite Error: " << err << "\n";
            sqlite3_free(err);
        }
    }

    static void WorkerLoop() {
        while (g_running) {
            std::vector<WriteTask> batch;
            {
                std::unique_lock<std::mutex> lk(g_queueMutex);
                g_queueCond.wait_for(lk, std::chrono::milliseconds(100), [] {
                    return !g_writeQueue.empty() || !g_running;
                });
                
                while (!g_writeQueue.empty()) {
                    batch.push_back(g_writeQueue.front());
                    g_writeQueue.pop();
                }
            }

            if (batch.empty()) continue;

            std::lock_guard<std::mutex> dbLock(g_dbMutex);
            sqlite3_exec(g_db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

            sqlite3_stmt* stmt = nullptr;
            const char* sql = R"(
                INSERT OR REPLACE INTO flows (
                    id, session_id, ts, type, method, url, host, port, status,
                    duration_ms, req_size, rsp_size, content_type, query_params,
                    cookies, body_preview, raw_req_headers, raw_rsp_headers,
                    insight_tags, process_hint, http_version, tls_valid, tls_sni,
                    redirect_chain, form_data, ws_message, ws_opcode, bandwidth_bps
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )";

            if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                for (const auto& task : batch) {
                    const auto& f = task.flow;
                    sqlite3_bind_text(stmt, 1, f.id.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(stmt, 2, task.sessionId);
                    sqlite3_bind_double(stmt, 3, f.ts);
                    sqlite3_bind_text(stmt, 4, f.type.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 5, f.method.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 6, f.url.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 7, f.host.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(stmt, 8, f.port);
                    sqlite3_bind_int(stmt, 9, f.status);
                    sqlite3_bind_double(stmt, 10, f.duration_ms);
                    sqlite3_bind_int64(stmt, 11, f.req_size);
                    sqlite3_bind_int64(stmt, 12, f.rsp_size);
                    sqlite3_bind_text(stmt, 13, f.content_type.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 14, f.query_params.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 15, f.cookies.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 16, f.body_preview.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 17, f.raw_req_headers.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 18, f.raw_rsp_headers.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 19, f.insight_tags.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 20, f.process_hint.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 21, f.http_version.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(stmt, 22, f.tls_valid ? 1 : 0);
                    sqlite3_bind_text(stmt, 23, f.tls_sni.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 24, f.redirect_chain.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 25, f.form_data.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 26, f.ws_message.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(stmt, 27, f.ws_opcode);
                    sqlite3_bind_int64(stmt, 28, f.bandwidth_bps);
                    
                    sqlite3_step(stmt);
                    sqlite3_reset(stmt);
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_exec(g_db, "COMMIT;", nullptr, nullptr, nullptr);
        }
    }

    bool Initialize(const std::string& dbPath) {
        std::lock_guard<std::mutex> lk(g_dbMutex);
        if (sqlite3_open(dbPath.c_str(), &g_db) != SQLITE_OK) {
            return false;
        }

        ExecuteSQL(R"(
            CREATE TABLE IF NOT EXISTS sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT    NOT NULL,
                started_at REAL    NOT NULL,
                ended_at   REAL    DEFAULT NULL
            );
        )");

        ExecuteSQL(R"(
            CREATE TABLE IF NOT EXISTS flows (
                id              TEXT    PRIMARY KEY,
                session_id      INTEGER NOT NULL,
                ts              REAL,
                type            TEXT,
                method          TEXT,
                url             TEXT,
                host            TEXT,
                port            INTEGER,
                status          INTEGER,
                duration_ms     REAL,
                req_size        INTEGER,
                rsp_size        INTEGER,
                content_type    TEXT,
                query_params    TEXT,
                cookies         TEXT,
                body_preview    TEXT,
                raw_req_headers TEXT,
                raw_rsp_headers TEXT,
                insight_tags    TEXT,
                process_hint    TEXT,
                http_version    TEXT,
                tls_valid       INTEGER,
                tls_sni         TEXT,
                redirect_chain  TEXT,
                form_data       TEXT,
                ws_message      TEXT,
                ws_opcode       INTEGER,
                bandwidth_bps   INTEGER,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            );
        )");

        ExecuteSQL("CREATE INDEX IF NOT EXISTS idx_flows_session ON flows(session_id);");
        ExecuteSQL("CREATE INDEX IF NOT EXISTS idx_flows_host    ON flows(host);");
        ExecuteSQL("CREATE INDEX IF NOT EXISTS idx_flows_ts      ON flows(ts);");

        g_running = true;
        g_workerThread = std::thread(WorkerLoop);
        return true;
    }

    void Shutdown() {
        g_running = false;
        g_queueCond.notify_all();
        if (g_workerThread.joinable()) {
            g_workerThread.join();
        }

        std::lock_guard<std::mutex> lk(g_dbMutex);
        if (g_db) {
            sqlite3_close(g_db);
            g_db = nullptr;
        }
    }

    int StartSession(const std::string& name) {
        std::lock_guard<std::mutex> lk(g_dbMutex);
        sqlite3_stmt* stmt = nullptr;
        int id = -1;
        if (sqlite3_prepare_v2(g_db, "INSERT INTO sessions (name, started_at) VALUES (?, ?)", -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(stmt, 2, (double)time(NULL));
            if (sqlite3_step(stmt) == SQLITE_DONE) {
                id = (int)sqlite3_last_insert_rowid(g_db);
            }
            sqlite3_finalize(stmt);
        }
        return id;
    }

    void EndSession(int sessionId) {
        std::lock_guard<std::mutex> lk(g_dbMutex);
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(g_db, "UPDATE sessions SET ended_at = ? WHERE id = ?", -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_double(stmt, 1, (double)time(NULL));
            sqlite3_bind_int(stmt, 2, sessionId);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    std::vector<std::pair<int, std::string>> GetAllSessions() {
        std::lock_guard<std::mutex> lk(g_dbMutex);
        std::vector<std::pair<int, std::string>> sessions;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(g_db, "SELECT id, name FROM sessions ORDER BY id DESC", -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int id = sqlite3_column_int(stmt, 0);
                const char* name = (const char*)sqlite3_column_text(stmt, 1);
                sessions.push_back({id, name ? name : "Unnamed"});
            }
            sqlite3_finalize(stmt);
        }
        return sessions;
    }

    void QueueFlowInsert(int sessionId, const ProxyFlow& flow) {
        std::lock_guard<std::mutex> lk(g_queueMutex);
        g_writeQueue.push({sessionId, flow});
        g_queueCond.notify_one();
    }

    std::vector<ProxyFlow> LoadFlowsForSession(int sessionId, int limit, int offset) {
        std::lock_guard<std::mutex> lk(g_dbMutex);
        std::vector<ProxyFlow> flows;
        
        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT id, ts, type, method, url, host, port, status, duration_ms, req_size, rsp_size, content_type, query_params, cookies, body_preview, raw_req_headers, raw_rsp_headers, insight_tags, process_hint, http_version, tls_valid, tls_sni, redirect_chain, form_data, ws_message, ws_opcode, bandwidth_bps FROM flows WHERE session_id = ? ORDER BY ts DESC LIMIT ? OFFSET ?";
        
        if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, sessionId);
            sqlite3_bind_int(stmt, 2, limit);
            sqlite3_bind_int(stmt, 3, offset);
            
            auto safe_text = [](sqlite3_stmt* stmt, int col) -> std::string {
                const char* t = (const char*)sqlite3_column_text(stmt, col);
                return t ? std::string(t) : "";
            };
            
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                ProxyFlow f;
                f.id = safe_text(stmt, 0);
                f.ts = sqlite3_column_double(stmt, 1);
                f.type = safe_text(stmt, 2);
                f.method = safe_text(stmt, 3);
                f.url = safe_text(stmt, 4);
                f.host = safe_text(stmt, 5);
                f.port = sqlite3_column_int(stmt, 6);
                f.status = sqlite3_column_int(stmt, 7);
                f.duration_ms = sqlite3_column_double(stmt, 8);
                f.req_size = sqlite3_column_int64(stmt, 9);
                f.rsp_size = sqlite3_column_int64(stmt, 10);
                f.content_type = safe_text(stmt, 11);
                f.query_params = safe_text(stmt, 12);
                f.cookies = safe_text(stmt, 13);
                f.body_preview = safe_text(stmt, 14);
                f.raw_req_headers = safe_text(stmt, 15);
                f.raw_rsp_headers = safe_text(stmt, 16);
                f.insight_tags = safe_text(stmt, 17);
                f.process_hint = safe_text(stmt, 18);
                f.http_version = safe_text(stmt, 19);
                f.tls_valid = sqlite3_column_int(stmt, 20) != 0;
                f.tls_sni = safe_text(stmt, 21);
                f.redirect_chain = safe_text(stmt, 22);
                f.form_data = safe_text(stmt, 23);
                f.ws_message = safe_text(stmt, 24);
                f.ws_opcode = sqlite3_column_int(stmt, 25);
                f.bandwidth_bps = sqlite3_column_int64(stmt, 26);
                flows.push_back(f);
            }
            sqlite3_finalize(stmt);
        }
        return flows;
    }

    void ClearDatabase() {
        if (!g_db) return;
        char* errMsg = nullptr;
        sqlite3_exec(g_db, "DELETE FROM flows; DELETE FROM sessions;", nullptr, nullptr, &errMsg);
        if (errMsg) {
            sqlite3_free(errMsg);
        }
    }
}
