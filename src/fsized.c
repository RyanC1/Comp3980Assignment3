#include "argumentsd.h"
#include "contextd.h"
#include "errors.h"
#include "util.h"
#include <ctype.h>
#include <fcntl.h>
#include <p101_c/p101_stdlib.h>
#include <p101_c/p101_string.h>
#include <p101_convert/integer.h>
#include <p101_fsm/fsm.h>
#include <p101_posix/p101_unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

enum states
{
    PARSE_ARGS = P101_FSM_USER_START,
    HANDLE_ARGS,
    WAIT_FOR_REQUEST,
    HANDLE_REQUESTS,
    USAGE,
    CLEANUP,
};

static volatile sig_atomic_t exit_flag           = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t client_socket_close = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static void             setup_signal_handlers(void);
static void             sig_handler(int signal);
static p101_fsm_state_t parse_arguments(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state_t handle_arguments(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state_t wait_for_request(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state_t handle_requests(const struct p101_env *env, struct p101_error *err, void *context);
static void             handle_new_connection(const struct p101_env *env, struct p101_error *err, int socket_fd, int **client_sockets, nfds_t *max_clients, struct pollfd **fds);
static void             handle_client_data(const struct p101_env *env, struct p101_error *err, int client_socket);
static char            *read_client_file(const struct p101_env *env, struct p101_error *err, char *filepath);
static void             respond(const struct p101_env *env, struct p101_error *err, int client_socket, const char *message);
static void             handle_client_disconnection(const struct p101_env *env, struct p101_error *err, int **client_sockets, nfds_t *max_clients, struct pollfd **fds, nfds_t client_index);
static p101_fsm_state_t usage(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state_t cleanup(const struct p101_env *env, struct p101_error *err, void *context);

#define MSG_LEN 256    // NOLINT(cppcoreguidelines-macro-to-enum, modernize-macro-to-enum)
#define SIZE_LEN 21    // NOLINT(cppcoreguidelines-macro-to-enum, modernize-macro-to-enum)

static void setup_signal_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(struct sigaction));

#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif
    action.sa_handler = sig_handler;
#ifdef __clang__
    #pragma clang diagnostic pop
#endif

    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if(sigaction(SIGINT, &action, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

static void sig_handler(int signal)
{
    if(signal == SIGINT)
    {
        exit_flag = 1;
    }
    else if(signal == SIGPIPE)
    {
        client_socket_close = 1;
    }
}

int main(int argc, char *argv[])
{
    static struct p101_fsm_transition transitions[] = {
        {P101_FSM_INIT,    PARSE_ARGS,       parse_arguments },
        {PARSE_ARGS,       HANDLE_ARGS,      handle_arguments},
        {PARSE_ARGS,       USAGE,            usage           },
        {HANDLE_ARGS,      WAIT_FOR_REQUEST, wait_for_request},
        {HANDLE_ARGS,      CLEANUP,          cleanup         },
        {WAIT_FOR_REQUEST, HANDLE_REQUESTS,  handle_requests },
        {WAIT_FOR_REQUEST, CLEANUP,          cleanup         },
        {HANDLE_REQUESTS,  WAIT_FOR_REQUEST, wait_for_request},
        {HANDLE_REQUESTS,  CLEANUP,          cleanup         },
        {USAGE,            CLEANUP,          cleanup         },
        {CLEANUP,          P101_FSM_EXIT,    NULL            }
    };

    struct p101_error    *err;
    struct p101_env      *env;
    struct p101_fsm_info *fsm;
    p101_fsm_state_t      from_state;
    p101_fsm_state_t      to_state;
    struct p101_error    *fsm_err;
    struct p101_env      *fsm_env;
    struct argumentsd     args;
    struct contextd       ctx;

    setup_signal_handlers();

    err = p101_error_create(false);

    if(err == NULL)
    {
        ctx.exit_code = EXIT_FAILURE;
        goto done;
    }

    env = p101_env_create(err, true, NULL);

    if(p101_error_has_error(err))
    {
        ctx.exit_code = EXIT_FAILURE;
        goto free_error;
    }

    fsm_err = p101_error_create(false);

    if(fsm_err == NULL)
    {
        ctx.exit_code = EXIT_FAILURE;
        goto free_env;
    }

    fsm_env = p101_env_create(err, true, NULL);

    if(p101_error_has_error(err))
    {
        ctx.exit_code = EXIT_FAILURE;
        goto free_fsm_error;
    }

    p101_memset(env, &args, 0, sizeof(args));
    p101_memset(env, &ctx, 0, sizeof(ctx));
    ctx.arguments       = &args;
    ctx.arguments->argc = argc;
    ctx.arguments->argv = argv;
    ctx.exit_code       = EXIT_SUCCESS;

    // p101_env_set_tracer(env, p101_env_default_tracer);

    fsm = p101_fsm_info_create(env, err, "fsized-fsm", fsm_env, fsm_err, NULL);

    // p101_fsm_info_set_did_change_state_notifier(fsm, p101_fsm_info_default_did_change_state_notifier);    // TODO

    p101_fsm_run(fsm, &from_state, &to_state, &ctx, transitions, sizeof(transitions));
    p101_fsm_info_destroy(env, &fsm);

    free(fsm_env);

free_fsm_error:
    p101_error_reset(fsm_err);
    p101_free(env, fsm_err);

free_env:
    p101_free(env, env);

free_error:
    p101_error_reset(err);
    free(err);

done:
    return ctx.exit_code;
}

static p101_fsm_state_t parse_arguments(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct contextd *ctx;
    p101_fsm_state_t next_state;
    int              opt;

    P101_TRACE(env);
    ctx                          = (struct contextd *)context;
    ctx->arguments->program_name = ctx->arguments->argv[0];
    next_state                   = HANDLE_ARGS;
    opterr                       = 0;

    while((opt = p101_getopt(env, ctx->arguments->argc, ctx->arguments->argv, "h")) != -1 && p101_error_has_no_error(err))
    {
        switch(opt)
        {
            case 'h':
            {
                next_state = USAGE;
                break;
            }
            case '?':
            {
                char msg[MSG_LEN];

                if(isprint(optopt))
                {
                    snprintf(msg, sizeof msg, "Unknown option '-%c'.", optopt);
                }
                else
                {
                    snprintf(msg, sizeof msg, "Unknown option character 0x%02X.", (unsigned)(unsigned char)optopt);
                }

                P101_ERROR_RAISE_USER(err, msg, ERR_USAGE);
                break;
            }
            default:
            {
                char msg[MSG_LEN];

                snprintf(msg, sizeof msg, "Internal error: unhandled option '-%c' returned by getopt.", isprint(opt) ? opt : '?');
                P101_ERROR_RAISE_USER(err, msg, ERR_USAGE);
                break;
            }
        }
    }

    if(p101_error_has_no_error(err) && next_state != USAGE)
    {
        if(optind >= ctx->arguments->argc)
        {
            P101_ERROR_RAISE_USER(err, "Socket path must be specified", ERR_USAGE);
        }
        else if(optind < ctx->arguments->argc - 1)
        {
            P101_ERROR_RAISE_USER(err, "Too many unnamed arguments", ERR_USAGE);
        }
        else
        {
            ctx->arguments->socket_path = ctx->arguments->argv[optind];
        }
    }

    if(p101_error_is_error(err, P101_ERROR_USER, ERR_USAGE))
    {
        next_state = USAGE;
    }

    return next_state;
}

p101_fsm_state_t handle_arguments(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct contextd   *ctx;
    p101_fsm_state_t   next_state;
    struct sockaddr_un addr;

    P101_TRACE(env);
    ctx        = (struct contextd *)context;
    next_state = WAIT_FOR_REQUEST;

    unlink(ctx->arguments->socket_path);

    ctx->socket_fd = create_un_socket();

    if(ctx->socket_fd == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed to create to socket", ERR_SOCKET);
        goto done;
    }

    if(init_un_addr(&addr, ctx->arguments->socket_path) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed to create create unix socket address", ERR_SOCKET);
        goto done;
    }

    if(bind(ctx->socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed to bind to socket", ERR_SOCKET);
        goto done;
    }

    if(listen(ctx->socket_fd, SOMAXCONN) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed to listen to socket", ERR_SOCKET);
        goto done;
    }

    ctx->fds = (struct pollfd *)p101_malloc(env, err, (1) * sizeof(struct pollfd));

    if(p101_error_has_no_error(err))
    {
        ctx->fds[0].fd     = ctx->socket_fd;
        ctx->fds[0].events = POLLIN;
    }

done:

    if(p101_error_has_error(err))
    {
        next_state = CLEANUP;
    }
    else
    {
        printf("Server open.\n");
    }

    return next_state;
}

static p101_fsm_state_t wait_for_request(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct contextd *ctx;
    p101_fsm_state_t next_state;
    int              poll_result;

    P101_TRACE(env);
    ctx        = (struct contextd *)context;
    next_state = HANDLE_REQUESTS;

    poll_result = poll(ctx->fds, ctx->max_clients + 1, -1);

    if(exit_flag)
    {
        next_state = CLEANUP;
        printf("Closing server...\n");
    }
    else if(poll_result < 0)
    {
        P101_ERROR_RAISE_USER(err, "Poll failed", ERR_OTHER);
        next_state = CLEANUP;
    }

    return next_state;
}

static p101_fsm_state_t handle_requests(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct contextd *ctx;
    p101_fsm_state_t next_state;

    P101_TRACE(env);
    ctx        = (struct contextd *)context;
    next_state = WAIT_FOR_REQUEST;

    if(ctx->fds[0].revents & POLLIN)
    {
        handle_new_connection(env, err, ctx->socket_fd, &ctx->client_sockets, &ctx->max_clients, &ctx->fds);
    }

    if(p101_error_has_error(err))
    {
        goto done;
    }

    for(nfds_t i = 0; i < ctx->max_clients; i++)
    {
        if(ctx->client_sockets[i] != -1 && (ctx->fds[i + 1].revents & POLLIN))
        {
            handle_client_data(env, err, ctx->client_sockets[i]);

            if(p101_error_has_no_error(err))
            {
                handle_client_disconnection(env, err, &ctx->client_sockets, &ctx->max_clients, &ctx->fds, i);
            }
        }
    }

done:
    if(p101_error_has_error(err))
    {
        next_state = CLEANUP;
    }

    return next_state;
}

void handle_new_connection(const struct p101_env *env, struct p101_error *err, int socket_fd, int **client_sockets, nfds_t *max_clients, struct pollfd **fds)
{
    int            new_socket;
    int           *temp_client_sockets;
    struct pollfd *new_fds;

    P101_TRACE(env);

    new_socket = accept(socket_fd, NULL, NULL);

    if(new_socket == -1)
    {
        P101_ERROR_RAISE_USER(err, "Accept failed", ERR_SOCKET);
        goto done;
    }

    (*max_clients)++;
    temp_client_sockets = (int *)p101_realloc(env, err, *client_sockets, sizeof(int) * (*max_clients));

    if(temp_client_sockets == NULL)
    {
        goto done;
    }

    *client_sockets                     = temp_client_sockets;
    (*client_sockets)[*max_clients - 1] = new_socket;

    new_fds = (struct pollfd *)p101_realloc(env, err, *fds, (*max_clients + 1) * sizeof(struct pollfd));

    if(new_fds != NULL)
    {
        *fds                        = new_fds;
        (*fds)[*max_clients].fd     = new_socket;
        (*fds)[*max_clients].events = POLLIN;
    }

done:
    return;
}

void handle_client_data(const struct p101_env *env, struct p101_error *err, int client_socket)
{
    char    *filename;
    uint16_t filename_length;
    char    *file_details;

    P101_TRACE(env);

    filename     = NULL;
    file_details = NULL;

    if(safe_read(client_socket, &filename_length, sizeof(uint16_t), true) < 0)
    {
        respond(env, err, client_socket, "Server failed to parse size of filename");
        goto done;
    }

    filename = (char *)p101_malloc(env, err, filename_length);

    if(p101_error_has_error(err))
    {
        goto done;
    }

    if(safe_read(client_socket, filename, filename_length, true) < 0)
    {
        respond(env, err, client_socket, "Server failed to parse filename");
        goto done;
    }

    file_details = read_client_file(env, err, filename);

    if(p101_error_has_no_error(err) && file_details != NULL)
    {
        respond(env, err, client_socket, file_details);
    }

done:
    p101_free(env, file_details);
    p101_free(env, filename);
}

static char *read_client_file(const struct p101_env *env, struct p101_error *err, char *filepath)
{
    int         client_fd;
    char       *response;
    struct stat file_stat;
    char        size[SIZE_LEN];

    P101_TRACE(env);

    response  = NULL;
    client_fd = open(filepath, O_RDONLY | O_CLOEXEC | O_NONBLOCK);

    if(client_fd == -1)
    {
        response = concat_string("Server could not open file: ", filepath);
        goto done;
    }

    if(fstat(client_fd, &file_stat) == -1)
    {
        response = concat_string("Server could not create fstat of: ", filepath);
        goto done;
    }

    if(!S_ISREG(file_stat.st_mode))
    {
        response = concat_string(filepath, " is not a regular file");
        goto done;
    }

    snprintf(size, sizeof(size), "%ld", file_stat.st_size);

    response = concat_string("Size in bytes: ", size);

done:
    if(client_fd > 0 && p101_close(env, err, client_fd) == -1)
    {
        p101_error_reset(err);
        P101_ERROR_RAISE_USER(err, "Failed to close file client sent", ERR_OTHER);
    }
    if(response == NULL && p101_error_has_no_error(err))
    {
        P101_ERROR_RAISE_USER(err, "Failed to allocate memory for message to send to client", ERR_OTHER);
    }

    return response;
}

static void respond(const struct p101_env *env, struct p101_error *err, int client_socket, const char *message)
{
    uint16_t    message_length;
    const char *actual_message;

    P101_TRACE(env);

    if(strlen(message) + 1 > UINT16_MAX)
    {
        actual_message = "Response too big to send";
        printf("Response \"%s\" too large to send.\n", message);
    }
    else
    {
        actual_message = message;
    }

    message_length = (uint16_t)(strlen(message) + 1);

    safe_write(client_socket, &message_length, sizeof(uint16_t));
    safe_write(client_socket, actual_message, message_length);

    if(client_socket_close == 1)
    {
        printf("Client Socket closed before response \"%s\" finished.\n", message);
        client_socket_close = 0;
    }
    else
    {
        printf("Successfully sent response \"%s\" to client.\n", message);
    }

    if(shutdown(client_socket, SHUT_RD | SHUT_WR))
    {
        P101_ERROR_RAISE_USER(err, "Failed shutdown client socket", ERR_SOCKET);
    }
}

static void handle_client_disconnection(const struct p101_env *env, struct p101_error *err, int **client_sockets, nfds_t *max_clients, struct pollfd **fds, nfds_t client_index)
{
    int disconnected_socket;

    P101_TRACE(env);

    disconnected_socket = (*client_sockets)[client_index];

    if(disconnected_socket > 0 && p101_close(env, err, disconnected_socket) == -1)
    {
        p101_error_reset(err);
        P101_ERROR_RAISE_USER(err, "Failed to close client connection", ERR_SOCKET);
    }
    else
    {
        for(nfds_t i = client_index; i < *max_clients - 1; i++)
        {
            (*client_sockets)[i] = (*client_sockets)[i + 1];
        }

        (*max_clients)--;

        for(nfds_t i = client_index + 1; i <= *max_clients; i++)
        {
            (*fds)[i] = (*fds)[i + 1];
        }
    }
}

static p101_fsm_state_t usage(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct contextd *ctx;

    P101_TRACE(env);
    ctx = (struct contextd *)context;

    if(p101_error_has_error(err))
    {
        const char *msg;
        msg = p101_error_get_message(err);

        if(msg != NULL)
        {
            fputs(msg, stderr);
            fputc('\n', stderr);
        }

        p101_error_reset(err);
        ctx->exit_code = EXIT_FAILURE;
    }

    fprintf(stderr, "Usage: %s [-h] <socket-path> \n", ctx->arguments->program_name);
    fputs("Options:\n", stderr);
    fputs("  -h                Display this help message and exit\n", stderr);
    fputs("  <socket-path>     Path to the domain socket (required)\n", stderr);

    return CLEANUP;
}

static p101_fsm_state_t cleanup(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct contextd *ctx;

    P101_TRACE(env);
    ctx = (struct contextd *)context;

    if(p101_error_has_error(err))
    {
        const char *msg;
        msg = p101_error_get_message(err);

        if(msg != NULL)
        {
            fputs(msg, stderr);
            fputc('\n', stderr);
        }

        p101_error_reset(err);
        ctx->exit_code = EXIT_FAILURE;
    }

    free(ctx->fds);

    for(size_t i = 0; i < ctx->max_clients; i++)
    {
        if(ctx->client_sockets[i] > 0)
        {
            p101_close(env, err, ctx->client_sockets[i]);
            if(p101_error_has_error(err))
            {
                fputs(p101_error_get_message(err), stderr);
                fputc('\n', stderr);
                p101_error_reset(err);
            }
            else
            {
                ctx->client_sockets[i] = -1;
            }
        }
    }

    free(ctx->client_sockets);

    if(ctx->socket_fd > 0 && p101_close(env, err, ctx->socket_fd) == -1)
    {
        fputs(p101_error_get_message(err), stderr);
        fputc('\n', stderr);
        p101_error_reset(err);
    }
    else
    {
        ctx->socket_fd = -1;
    }

    if(ctx->arguments->socket_path != NULL)
    {
        unlink(ctx->arguments->socket_path);
    }

    return P101_FSM_EXIT;
}
