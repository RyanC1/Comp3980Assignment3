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
#include <p101_posix/p101_string.h>
#include <p101_posix/p101_unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/socket.h>
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

static volatile sig_atomic_t exit_flag = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static void           setup_signal_handlers(void);
static void           sig_handler(int signal);
static p101_fsm_state parse_arguments(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state handle_arguments(const struct p101_env *env, struct p101_error *err, void *context);
static int            socket_create(const struct p101_env *env, struct p101_error *err);
static void           socket_bind(const struct p101_env *env, struct p101_error *err, int socket_fd, const char *path);
static void           socket_close(const struct p101_env *env, struct p101_error *err, int socket_fd);
static p101_fsm_state wait_for_request(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state handle_requests(const struct p101_env *env, struct p101_error *err, void *context);
static void           handle_new_connection(const struct p101_env *env, struct p101_error *err, int socket_fd, int **client_sockets, nfds_t *max_clients, struct pollfd **fds);
static void           handle_client_data(const struct p101_env *env, struct p101_error *err, struct pollfd fd, int client_socket, nfds_t *max_clients);
static void           handle_client_disconnection(const struct p101_env *env, struct p101_error *err, int **client_sockets, nfds_t *max_clients, struct pollfd **fds, nfds_t client_index);
static p101_fsm_state respond(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state cleanup_response(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state usage(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state cleanup_program(const struct p101_env *env, struct p101_error *err, void *context);

#define MSG_LEN 256    // NOLINT(cppcoreguidelines-macro-to-enum, modernize-macro-to-enum)

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
}

int main(int argc, char *argv[])
{
    static struct p101_fsm_transition transitions[] = {

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

    fsm = p101_fsm_info_create(env, err, "fsized-fsm", fsm_env, fsm_err, NULL);

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

static p101_fsm_state parse_arguments(const struct p101_env *env, struct p101_error *err, void *context)
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

p101_fsm_state handle_arguments(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct contextd *ctx;
    p101_fsm_state_t next_state;

    P101_TRACE(env);
    ctx        = (struct contextd *)context;
    next_state = WAIT_FOR_REQUEST;

    unlink(ctx->arguments->socket_path);

    ctx->socket_fd = socket_create(env, err);

    if(p101_error_has_no_error(err))
    {
        socket_bind(env, err, ctx->socket_fd, ctx->arguments->socket_path);

        if(p101_error_has_no_error(err))
        {
            if(listen(ctx->socket_fd, SOMAXCONN) == -1)
            {
                P101_ERROR_RAISE_USER(err, "Failed to listen to socket", ERR_SOCKET);
            }
        }
    }

    else if(p101_error_has_error(err))
    {
        next_state = CLEANUP;
    }

    return next_state;
}

static int socket_create(const struct p101_env *env, struct p101_error *err)
{
    int socket_fd;

    P101_TRACE(env);

#ifdef SOCK_CLOEXEC
    socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)
#endif

    if(socket_fd == -1)
    {
        P101_ERROR_RAISE_USER(err, "Socket creation failed", ERR_SOCKET);
    }

    return socket_fd;
}

static void socket_bind(const struct p101_env *env, struct p101_error *err, int socket_fd, const char *path)
{
    struct sockaddr_un addr;

    P101_TRACE(env);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    if(bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed to bind socket", ERR_SOCKET);
    }
}

static void socket_close(const struct p101_env *env, struct p101_error *err, int socket_fd)
{
    P101_TRACE(env);

    if(close(socket_fd) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Socket closure failed", ERR_SOCKET);
    }

    printf("Socket closed.\n");
}

static p101_fsm_state wait_for_request(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct contextd *ctx;
    p101_fsm_state_t next_state;

    P101_TRACE(env);
    ctx        = (struct contextd *)context;
    next_state = HANDLE_REQUESTS;

    int activity;

    activity = poll(ctx->fds, ctx->max_clients + 1, -1);

    if(exit_flag)
    {
        next_state = CLEANUP;
    }
    else if(activity < 0)
    {
        P101_ERROR_RAISE_USER(err, "Poll failed", ERR_SOCKET);
        next_state = CLEANUP;
    }

    return next_state;
}

static p101_fsm_state handle_requests(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct contextd *ctx;
    p101_fsm_state_t next_state;

    P101_TRACE(env);
    ctx        = (struct contextd *)context;
    next_state = WAIT_FOR_REQUEST;

    handle_new_connection(env, err, ctx->socket_fd, &ctx->client_sockets, &ctx->max_clients, &ctx->fds);

    if(ctx->client_sockets != NULL)
    {
        for(nfds_t i = 0; i < ctx->max_clients; i++)
        {
            handle_client_data(env, err, ctx->fds[i + 1], ctx->client_sockets[i], &ctx->max_clients);
        }
    }
}

void handle_new_connection(const struct p101_env *env, struct p101_error *err, int socket_fd, int **client_sockets, nfds_t *max_clients, struct pollfd **fds)
{
    P101_TRACE(env);

    if((*fds)[0].revents & POLLIN)
    {
        socklen_t          addrlen;
        int                new_socket;
        int               *temp;
        struct sockaddr_un addr;

        addrlen    = sizeof(addr);
        new_socket = accept(socket_fd, (struct sockaddr *)&addr, &addrlen);

        if(new_socket == -1)
        {
            P101_ERROR_RAISE_USER(err, "Accept failed", ERR_SOCKET);
        }
        else
        {
            (*max_clients)++;
            temp = (int *)p101_realloc(env, err, *client_sockets, sizeof(int) * (*max_clients));

            if(p101_error_has_no_error(err))
            {
                struct pollfd *new_fds;
                *client_sockets                       = temp;
                (*client_sockets)[*max_clients - 1] = new_socket;

                new_fds = (struct pollfd *)p101_realloc(env, err, *fds, (*max_clients + 1) * sizeof(struct pollfd));

                if(p101_error_has_no_error(err))
                {
                    *fds                        = new_fds;
                    (*fds)[*max_clients].fd     = new_socket;
                    (*fds)[*max_clients].events = POLLIN;
                }
            }
        }

    }
}

void handle_client_data(const struct p101_env *env, struct p101_error *err, struct pollfd fds, int client_socket, nfds_t *max_clients)
{
    P101_TRACE(env);

    if(client_socket != -1 && (fds.revents & POLLIN))
    {
        uint16_t filename_length;

        if(safe_read(client_socket, &filename_length, sizeof(uint16_t),true) < 0)
        {
            // Connection closed or error
            printf("Client %d disconnected\n", client_socket);
            // handle_client_disconnection(&client_socket, max_clients, &fds, i);
        }
        else
        {
            char * filename;
            filename = (char *)p101_malloc(env, err, filename_length);

            if(p101_error_has_no_error(err))
            {

            }
            else
            {
                if(safe_read(client_socket, filename, filename_length,true) < 0)
                {

                }
                else
                {
                    respond();
                    cleanup_response();
                }
            }



        }
    }
}

void handle_client_disconnection(const struct p101_env *env, struct p101_error *err, int **client_sockets, nfds_t *max_clients, struct pollfd **fds, nfds_t client_index)
{

}

p101_fsm_state respond(const struct p101_env *env, struct p101_error *err, int client_socket, char *filepath)
{
    int client_fd;

    P101_TRACE(env);

    client_fd = open(filepath, O_RDONLY);

    if(client_fd == -1)
    {

    }
    else
    {
        struct stat file_stat;

        if(fstat(client_fd, &file_stat) == -1)
        {

        }
        else
        {

        }

    }
}

p101_fsm_state cleanup_response(const struct p101_env *env, struct p101_error *err, void *context)
{

}

static p101_fsm_state usage(const struct p101_env *env, struct p101_error *err, void *context)
{
}

static p101_fsm_state cleanup_program(const struct p101_env *env, struct p101_error *err, void *context)
{
}
