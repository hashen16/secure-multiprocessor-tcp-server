
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <crypt.h>

#define REGNO "IT24123456"
#define LAST4 "3456"
#define SID "1234"
#define PORT 50456

#define BASE_DIR "/srv/ie2102/IT24123456"
#define LOG_FILE "server_IT24123456.log"

#define MAX_PAYLOAD 4096
#define BUFFER_CAP 8192

#define USERNAME_MIN 3
#define USERNAME_MAX 32

#define TOKEN_HEX_LEN 64
#define SALT_HEX_LEN 16

#define TOKEN_TIMEOUT 300

#define RATE_LIMIT_COUNT 20
#define RATE_LIMIT_WINDOW 60

#define LOGIN_FAIL_LIMIT 3
#define LOCKOUT_SECONDS 60

static int listen_fd = -1;
static volatile sig_atomic_t running = 1;

typedef struct {
    int logged_in;
    char username[USERNAME_MAX + 1];
    char token[TOKEN_HEX_LEN + 1];
    time_t last_activity;

    int login_failures;
    time_t locked_until;

    time_t rate_window_start;
    int rate_count;
} Session;

static void trim_newline(char *s) {
    if (!s) return;

    size_t len = strlen(s);

    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[len - 1] = '\0';
        len--;
    }
}

static int send_all(int fd, const char *data, size_t len) {
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);

        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }

        if (n == 0) return -1;

        sent += (size_t)n;
    }

    return 0;
}

static void send_response(int fd, const char *status, int code, const char *message) {
    char out[1024];

    snprintf(out, sizeof(out), "%s %d SID:%s %s\n", status, code, SID, message);

    send_all(fd, out, strlen(out));
}

static void make_timestamp(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm tm_info;

    localtime_r(&now, &tm_info);

    strftime(buf, size, "%Y-%m-%d %H:%M:%S", &tm_info);
}

static void log_event(const char *client_addr, const char *username, const char *command, const char *result) {
    int fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);

    if (fd < 0) return;

    flock(fd, LOCK_EX);

    char ts[64];
    make_timestamp(ts, sizeof(ts));

    dprintf(
        fd,
        "%s client=%s pid=%d user=%s cmd=%s result=%s\n",
        ts,
        client_addr ? client_addr : "unknown",
        getpid(),
        username && username[0] ? username : "-",
        command && command[0] ? command : "-",
        result && result[0] ? result : "-"
    );

    flock(fd, LOCK_UN);
    close(fd);
}

static void sigchld_handler(int sig) {
    (void)sig;

    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }

    errno = saved_errno;
}

static void stop_handler(int sig) {
    (void)sig;

    running = 0;

    if (listen_fd >= 0) {
        close(listen_fd);
    }
}

static void setup_signals(void) {
    struct sigaction sa_chld;
    memset(&sa_chld, 0, sizeof(sa_chld));

    sa_chld.sa_handler = sigchld_handler;
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART | SA_NOCLDSTOP;

    sigaction(SIGCHLD, &sa_chld, NULL);

    struct sigaction sa_stop;
    memset(&sa_stop, 0, sizeof(sa_stop));

    sa_stop.sa_handler = stop_handler;
    sigemptyset(&sa_stop.sa_mask);

    sigaction(SIGINT, &sa_stop, NULL);
    sigaction(SIGTERM, &sa_stop, NULL);
}

static int mkdir_p(const char *path) {
    char tmp[512];

    snprintf(tmp, sizeof(tmp), "%s", path);

    size_t len = strlen(tmp);

    if (len == 0) return -1;

    if (tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';

            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return -1;
            }

            *p = '/';
        }
    }

    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
    }

    return 0;
}

static int is_valid_username(const char *u) {
    if (!u) return 0;

    size_t len = strlen(u);

    if (len < USERNAME_MIN || len > USERNAME_MAX) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        if (!(isalnum((unsigned char)u[i]) || u[i] == '_')) {
            return 0;
        }
    }

    return 1;
}

static int random_hex(char *out, size_t hex_len) {
    if (hex_len % 2 != 0) return -1;

    size_t byte_len = hex_len / 2;

    unsigned char bytes[64];

    if (byte_len > sizeof(bytes)) return -1;

    int fd = open("/dev/urandom", O_RDONLY);

    if (fd < 0) return -1;

    size_t got = 0;

    while (got < byte_len) {
        ssize_t n = read(fd, bytes + got, byte_len - got);

        if (n < 0) {
            if (errno == EINTR) continue;

            close(fd);
            return -1;
        }

        if (n == 0) {
            close(fd);
            return -1;
        }

        got += (size_t)n;
    }

    close(fd);

    for (size_t i = 0; i < byte_len; i++) {
        sprintf(out + i * 2, "%02x", bytes[i]);
    }

    out[hex_len] = '\0';

    return 0;
}

static void user_dir_path(const char *username, char *out, size_t out_size) {
    snprintf(out, out_size, "%s/%s", BASE_DIR, username);
}

static void auth_file_path(const char *username, char *out, size_t out_size) {
    snprintf(out, out_size, "%s/%s/auth.txt", BASE_DIR, username);
}

static int create_password_hash(const char *password, char *out, size_t out_size) {
    char salt_hex[SALT_HEX_LEN + 1];

    if (random_hex(salt_hex, SALT_HEX_LEN) != 0) {
        return -1;
    }

    char salt_spec[64];

    snprintf(salt_spec, sizeof(salt_spec), "$6$%s$", salt_hex);

    char *hash = crypt(password, salt_spec);

    if (!hash) return -1;

    snprintf(out, out_size, "%s", hash);

    return 0;
}

static int verify_password(const char *password, const char *stored_hash) {
    char *calc = crypt(password, stored_hash);

    if (!calc) return 0;

    return strcmp(calc, stored_hash) == 0;
}

static int read_stored_hash(const char *username, char *out, size_t out_size) {
    char path[512];

    auth_file_path(username, path, sizeof(path));

    FILE *fp = fopen(path, "r");

    if (!fp) return -1;

    if (!fgets(out, (int)out_size, fp)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    trim_newline(out);

    return 0;
}

static int write_stored_hash(const char *username, const char *hash) {
    char dir[512];

    user_dir_path(username, dir, sizeof(dir));

    if (mkdir_p(dir) != 0) {
        return -1;
    }

    char path[512];

    auth_file_path(username, path, sizeof(path));

    FILE *fp = fopen(path, "w");

    if (!fp) return -1;

    fprintf(fp, "%s\n", hash);

    fclose(fp);

    chmod(path, 0600);

    return 0;
}

static int user_exists(const char *username) {
    char path[512];

    auth_file_path(username, path, sizeof(path));

    return access(path, F_OK) == 0;
}

static int check_rate_limit(Session *s) {
    time_t now = time(NULL);

    if (s->rate_window_start == 0 || now - s->rate_window_start >= RATE_LIMIT_WINDOW) {
        s->rate_window_start = now;
        s->rate_count = 1;
        return 1;
    }

    s->rate_count++;

    if (s->rate_count > RATE_LIMIT_COUNT) {
        return 0;
    }

    return 1;
}

static int check_token(Session *s, const char *token, char *err_msg, size_t err_size) {
    time_t now = time(NULL);

    if (!s->logged_in) {
        snprintf(err_msg, err_size, "NOT_LOGGED_IN");
        return 0;
    }

    if (!token || strlen(token) == 0) {
        snprintf(err_msg, err_size, "TOKEN_REQUIRED");
        return 0;
    }

    if (strcmp(token, s->token) != 0) {
        snprintf(err_msg, err_size, "TOKEN_INVALID");
        return 0;
    }

    if (now - s->last_activity > TOKEN_TIMEOUT) {
        s->logged_in = 0;
        s->username[0] = '\0';
        s->token[0] = '\0';

        snprintf(err_msg, err_size, "TOKEN_EXPIRED");

        return 0;
    }

    s->last_activity = now;

    return 1;
}

static void process_command(int client_fd, Session *session, const char *client_addr, const char *payload) {
    char work[MAX_PAYLOAD + 1];

    snprintf(work, sizeof(work), "%s", payload);

    trim_newline(work);

    char *argv[8];
    int argc = 0;

    char *saveptr = NULL;
    char *tok = strtok_r(work, " \t\r\n", &saveptr);

    while (tok && argc < 8) {
        argv[argc++] = tok;
        tok = strtok_r(NULL, " \t\r\n", &saveptr);
    }

    const char *cmd = argc > 0 ? argv[0] : "EMPTY";

    char result[256];

    if (!check_rate_limit(session)) {
        snprintf(result, sizeof(result), "ERR 429 RATE_LIMIT_EXCEEDED");
        send_response(client_fd, "ERR", 429, "RATE_LIMIT_EXCEEDED");
        log_event(client_addr, session->username, cmd, result);
        return;
    }

    if (argc == 0) {
        snprintf(result, sizeof(result), "ERR 400 EMPTY_COMMAND");
        send_response(client_fd, "ERR", 400, "EMPTY_COMMAND");
        log_event(client_addr, session->username, cmd, result);
        return;
    }

    if (strcmp(argv[0], "REGISTER") == 0) {
        if (argc != 3) {
            snprintf(result, sizeof(result), "ERR 400 REGISTER_USAGE");
            send_response(client_fd, "ERR", 400, "USAGE REGISTER <user> <pass>");
        } else if (!is_valid_username(argv[1])) {
            snprintf(result, sizeof(result), "ERR 400 INVALID_USERNAME");
            send_response(client_fd, "ERR", 400, "INVALID_USERNAME");
        } else if (strlen(argv[2]) < 4) {
            snprintf(result, sizeof(result), "ERR 400 WEAK_PASSWORD");
            send_response(client_fd, "ERR", 400, "WEAK_PASSWORD_MIN_4_CHARS");
        } else if (mkdir_p(BASE_DIR) != 0) {
            snprintf(result, sizeof(result), "ERR 500 BASE_DIR_ERROR");
            send_response(client_fd, "ERR", 500, "BASE_DIR_ERROR_CHECK_PERMISSIONS");
        } else if (user_exists(argv[1])) {
            snprintf(result, sizeof(result), "ERR 409 USER_EXISTS");
            send_response(client_fd, "ERR", 409, "USER_EXISTS");
        } else {
            char hash[256];

            if (create_password_hash(argv[2], hash, sizeof(hash)) != 0 ||
                write_stored_hash(argv[1], hash) != 0) {
                snprintf(result, sizeof(result), "ERR 500 REGISTER_FAILED");
                send_response(client_fd, "ERR", 500, "REGISTER_FAILED");
            } else {
                snprintf(result, sizeof(result), "OK 201 REGISTER_SUCCESS");
                send_response(client_fd, "OK", 201, "REGISTER_SUCCESS");
            }
        }

        log_event(client_addr, session->username, cmd, result);
        return;
    }

    if (strcmp(argv[0], "LOGIN") == 0) {
        time_t now = time(NULL);

        if (session->locked_until > now) {
            snprintf(result, sizeof(result), "ERR 423 ACCOUNT_LOCKED");
            send_response(client_fd, "ERR", 423, "ACCOUNT_LOCKED_WAIT_60_SECONDS");
            log_event(client_addr, session->username, cmd, result);
            return;
        }

        if (argc != 3) {
            snprintf(result, sizeof(result), "ERR 400 LOGIN_USAGE");
            send_response(client_fd, "ERR", 400, "USAGE LOGIN <user> <pass>");
        } else if (!is_valid_username(argv[1])) {
            snprintf(result, sizeof(result), "ERR 400 INVALID_USERNAME");
            send_response(client_fd, "ERR", 400, "INVALID_USERNAME");
        } else {
            char stored_hash[256];

            int ok =
                read_stored_hash(argv[1], stored_hash, sizeof(stored_hash)) == 0 &&
                verify_password(argv[2], stored_hash);

            if (!ok) {
                session->login_failures++;

                if (session->login_failures >= LOGIN_FAIL_LIMIT) {
                    session->locked_until = now + LOCKOUT_SECONDS;

                    snprintf(result, sizeof(result), "ERR 423 ACCOUNT_LOCKED");
                    send_response(client_fd, "ERR", 423, "ACCOUNT_LOCKED_WAIT_60_SECONDS");
                } else {
                    snprintf(result, sizeof(result), "ERR 401 INVALID_LOGIN");
                    send_response(client_fd, "ERR", 401, "INVALID_LOGIN");
                }
            } else {
                session->login_failures = 0;
                session->locked_until = 0;
                session->logged_in = 1;

                snprintf(session->username, sizeof(session->username), "%s", argv[1]);

                if (random_hex(session->token, TOKEN_HEX_LEN) != 0) {
                    session->logged_in = 0;
                    session->username[0] = '\0';

                    snprintf(result, sizeof(result), "ERR 500 TOKEN_GENERATION_FAILED");
                    send_response(client_fd, "ERR", 500, "TOKEN_GENERATION_FAILED");
                } else {
                    session->last_activity = now;

                    char msg[256];

                    snprintf(msg, sizeof(msg), "LOGIN_SUCCESS TOKEN:%s", session->token);

                    snprintf(result, sizeof(result), "OK 200 LOGIN_SUCCESS");

                    send_response(client_fd, "OK", 200, msg);
                }
            }
        }

        log_event(client_addr, session->username, cmd, result);
        return;
    }

    if (strcmp(argv[0], "LOGOUT") == 0) {
        char err[64];

        const char *token_arg = argc >= 2 ? argv[1] : NULL;

        char logged_user[USERNAME_MAX + 1];

        snprintf(logged_user, sizeof(logged_user), "%s", session->username);

        if (!check_token(session, token_arg, err, sizeof(err))) {
            snprintf(result, sizeof(result), "ERR 403 %s", err);
            send_response(client_fd, "ERR", 403, err);
            log_event(client_addr, session->username, cmd, result);
        } else {
            snprintf(result, sizeof(result), "OK 200 LOGOUT_SUCCESS");
            send_response(client_fd, "OK", 200, "LOGOUT_SUCCESS");

            log_event(client_addr, logged_user, cmd, result);

            session->logged_in = 0;
            session->username[0] = '\0';
            session->token[0] = '\0';
        }

        return;
    }

    if (strcmp(argv[0], "WHOAMI") == 0) {
        char err[64];

        const char *token_arg = argc >= 2 ? argv[1] : NULL;

        if (!check_token(session, token_arg, err, sizeof(err))) {
            snprintf(result, sizeof(result), "ERR 403 %s", err);
            send_response(client_fd, "ERR", 403, err);
        } else {
            char msg[128];

            snprintf(msg, sizeof(msg), "USER:%s", session->username);

            snprintf(result, sizeof(result), "OK 200 WHOAMI_SUCCESS");

            send_response(client_fd, "OK", 200, msg);
        }

        log_event(client_addr, session->username, cmd, result);
        return;
    }

    if (strcmp(argv[0], "PING") == 0) {
        char err[64];

        const char *token_arg = argc >= 2 ? argv[1] : NULL;

        if (!check_token(session, token_arg, err, sizeof(err))) {
            snprintf(result, sizeof(result), "ERR 403 %s", err);
            send_response(client_fd, "ERR", 403, err);
        } else {
            snprintf(result, sizeof(result), "OK 200 PONG");
            send_response(client_fd, "OK", 200, "PONG");
        }

        log_event(client_addr, session->username, cmd, result);
        return;
    }

    if (strcmp(argv[0], "HELP") == 0) {
        snprintf(result, sizeof(result), "OK 200 HELP");
        send_response(client_fd, "OK", 200, "COMMANDS REGISTER LOGIN LOGOUT WHOAMI PING HELP");
        log_event(client_addr, session->username, cmd, result);
        return;
    }

    snprintf(result, sizeof(result), "ERR 400 UNKNOWN_COMMAND");
    send_response(client_fd, "ERR", 400, "UNKNOWN_COMMAND");
    log_event(client_addr, session->username, cmd, result);
}

static int parse_length_header(const char *line, size_t line_len, long *out_len) {
    if (line_len < 5) return -1;

    if (strncmp(line, "LEN:", 4) != 0) return -1;

    char numbuf[32];

    size_t num_len = line_len - 4;

    if (num_len == 0 || num_len >= sizeof(numbuf)) {
        return -1;
    }

    memcpy(numbuf, line + 4, num_len);

    numbuf[num_len] = '\0';

    for (size_t i = 0; i < num_len; i++) {
        if (!isdigit((unsigned char)numbuf[i])) {
            return -1;
        }
    }

    char *end = NULL;

    errno = 0;

    long val = strtol(numbuf, &end, 10);

    if (errno != 0 || !end || *end != '\0' || val < 0) {
        return -1;
    }

    *out_len = val;

    return 0;
}

static void handle_client(int client_fd, struct sockaddr_in client_sa) {
    char ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &client_sa.sin_addr, ip, sizeof(ip));

    char client_addr[128];

    snprintf(client_addr, sizeof(client_addr), "%s:%d", ip, ntohs(client_sa.sin_port));

    Session session;

    memset(&session, 0, sizeof(session));

    log_event(client_addr, NULL, "CONNECT", "OK CONNECTED");

    send_response(client_fd, "OK", 100, "CONNECTED_TO_IE2102_SERVER");

    char buffer[BUFFER_CAP];

    size_t used = 0;

    while (1) {
        ssize_t n = recv(client_fd, buffer + used, sizeof(buffer) - used, 0);

        if (n < 0) {
            if (errno == EINTR) continue;

            log_event(client_addr, session.username, "RECV", "ERR RECV_FAILED");
            break;
        }

        if (n == 0) {
            log_event(client_addr, session.username, "DISCONNECT", "OK CLIENT_CLOSED");
            break;
        }

        used += (size_t)n;

        while (1) {
            char *newline = memchr(buffer, '\n', used);

            if (!newline) {
                if (used > 64) {
                    send_response(client_fd, "ERR", 400, "INVALID_HEADER_TOO_LONG");
                    log_event(client_addr, session.username, "PROTOCOL", "ERR INVALID_HEADER_TOO_LONG");
                    return;
                }

                break;
            }

            size_t line_len = (size_t)(newline - buffer);
            size_t header_total = line_len + 1;

            long payload_len = 0;

            if (parse_length_header(buffer, line_len, &payload_len) != 0) {
                send_response(client_fd, "ERR", 400, "INVALID_LENGTH_HEADER");
                log_event(client_addr, session.username, "PROTOCOL", "ERR INVALID_LENGTH_HEADER");
                return;
            }

            if (payload_len > MAX_PAYLOAD) {
                send_response(client_fd, "ERR", 413, "PAYLOAD_TOO_LARGE");
                log_event(client_addr, session.username, "PROTOCOL", "ERR PAYLOAD_TOO_LARGE");
                return;
            }

            if (used < header_total + (size_t)payload_len) {
                break;
            }

            char payload[MAX_PAYLOAD + 1];

            memcpy(payload, buffer + header_total, (size_t)payload_len);

            payload[payload_len] = '\0';

            process_command(client_fd, &session, client_addr, payload);

            size_t consumed = header_total + (size_t)payload_len;

            memmove(buffer, buffer + consumed, used - consumed);

            used -= consumed;
        }

        if (used == sizeof(buffer)) {
            send_response(client_fd, "ERR", 413, "BUFFER_OVERFLOW");
            log_event(client_addr, session.username, "PROTOCOL", "ERR BUFFER_OVERFLOW");
            break;
        }
    }
}

int main(void) {
    setup_signals();

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;

    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(listen_fd);
        return 1;
    }

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 20) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    printf("IE2102 TCP Server started\n");
    printf("REGNO=%s SID=%s PORT=%d PID=%d\n", REGNO, SID, PORT, getpid());
    printf("Log file: %s\n", LOG_FILE);
    fflush(stdout);

    while (running) {
        struct sockaddr_in client_sa;
        socklen_t client_len = sizeof(client_sa);

        int client_fd = accept(listen_fd, (struct sockaddr *)&client_sa, &client_len);

        if (client_fd < 0) {
            if (errno == EINTR) continue;
            if (!running) break;

            perror("accept");
            continue;
        }

        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            send_response(client_fd, "ERR", 500, "SERVER_FORK_FAILED");
            close(client_fd);
            continue;
        }

        if (pid == 0) {
            close(listen_fd);

            handle_client(client_fd, client_sa);

            close(client_fd);

            exit(0);
        } else {
            close(client_fd);
        }
    }

    printf("Server shutting down...\n");

    return 0;
}
