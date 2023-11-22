/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * This shell program is a tiny shell program with command line inputs.
 * It supports features such as job control, builtin commands (jobs, fg, bg,
 * quit), input and output redirection using <,>, executing external commands
 * and signal handling. The purpose is to get a better understanding of I/O and
 * Exceptional Contrl Flow and Signals.
 *
 * Specifications:
 * - Builtin Commands: quit, jobs, fg and bg.
 * - Job Control: Manages background and foreground processes, allowing the
 *   user to run processes in the background ('&'), bring background processes
 *   to the foreground, terminate (Ctrl-C) and stop (Ctrl-Z) and
 *   continue (SIGCONT) processes.
 * - Signal Handling: Intercepts and handles signals like SIGINT (Ctrl-C) and
 *   SIGTSTP (Ctrl-Z) for job control.
 * - I/O Redirection: Allow redirecting commands, such as > (outfile) and <
 *   (infile) make inputs and outpus to files.
 *
 * @author Yuhong YAO <yuhongy@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

volatile sig_atomic_t pid;

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/**
 * @brief Checks if a string represents a valid number.
 *
 * @param input The string to be checked.
 * @return true if the string is a valid number, false otherwise.
 */
bool is_number(const char *input) {
    while (*input) {
        if (!isdigit(*input)) {
            return false;
        }
        input++;
    }
    return true;
}

/**
 * @brief This function is used to parse the job_id or pid when we have builtin
 * bg and fg
 *
 * tell if it is a job_id or pid from input by checking if there is a % in the
 * second argv, and check if the following is number and get job id or pid, if
 * it is pid, use the job_from_pid to get the corresponding jid
 * @param token Struct that include user cmdline inputs tokens
 * @param pid_cmd Pointer to a boolean used to tell if it is a giving a pid not
 * job id
 * @param cmd_number Pointer to a boolean tell if the arguments after bg or fg
 * is number
 *
 * @return job_id
 */
jid_t get_jid(struct cmdline_tokens token, bool *pid_cmd, bool *cmd_number) {
    jid_t job_id = 0;
    if (token.argv[1][0] == '%') {
        if (is_number(&token.argv[1][1])) {
            job_id = atoi(&token.argv[1][1]);
            *cmd_number = true;
        }
    } else {
        if (is_number(&token.argv[1][1])) {
            pid = atoi(token.argv[1]);
            job_id = job_from_pid(pid);
            *pid_cmd = true;
            *cmd_number = true;
        }
    }
    return job_id;
}

/**
 * @brief Prints error messages for bg or fg commands.
 *
 * @param token struct that include user cmdline inputs tokens
 * @param cmd_number Boolean indicating if the command argument is a number.
 * @param pid_cmd Boolean indicating if a PID was provided.
 */
void print_error_builtin(struct cmdline_tokens token, bool cmd_number,
                         bool pid_cmd) {
    if (pid_cmd) {
        if (cmd_number) {
            sio_printf("(%s): No such job\n", token.argv[1]);
        } else {
            sio_printf("%s: argument must be a PID or %%jobid\n",
                       token.argv[0]);
        }
    } else {
        if (cmd_number) {
            sio_printf("%s: No such job\n", token.argv[1]);
        } else {
            sio_printf("%s: argument must be a PID or %%jobid\n",
                       token.argv[0]);
        }
    }
}

/**
 * @brief resume jobs by sending SIGCONT to those stopped job
 *
 * @param job_id The job id of the job to be resumed.
 * @param token Struct that include user cmdline inputs tokens
 * @param prev_mask The previous signal mask to restore after resuming the job.
 */
void resume_job(jid_t job_id, struct cmdline_tokens token, sigset_t prev_mask) {
    pid = job_get_pid(job_id);
    if (kill(-pid, SIGCONT) < 0) { // send SIGCONT signal to resume
        sio_eprintf("Error sending SIGCONT to job %d", job_id);
    } else {
        job_state state = (token.builtin == BUILTIN_BG) ? BG : FG;
        job_set_state(job_id, state);
        if (state == BG) {
            sio_printf("[%d] (%d) %s\n", job_id, pid, job_get_cmdline(job_id));
        } else {
            while (fg_job() != 0) {
                sigsuspend(&prev_mask);
            }
        }
    }
}

/**
 * @brief Redirects stdin to a file.
 *
 * This function opens a file for reading and duplicates its file descriptor
 * to STDIN_FILENO. It ensures that any read operations in the shell or a
 * child process will now read from the specified file instead of the standard
 * input.
 *
 * @param infile The path of the file to redirect input from.
 */
void input_redirection(const char *infile) {
    int infd = open(infile, O_RDONLY);
    if (infd < 0) {
        perror(infile);
        exit(1);
    }
    dup2(infd, STDIN_FILENO);
    close(infd);
}

/**
 * @brief Redirects stdout to a file.
 *
 * This function opens (or creates if it does not exist) a file for writing.
 * It sets the file's mode to allow read and write permissions for the user,
 * and read permissions for group and others. The file descriptor is then
 * duplicated to STDOUT_FILENO.
 *
 * @param outfile The path of the file to redirect output to.
 */
void output_redirection(const char *outfile) {
    int outfd =
        open(outfile, O_CREAT | O_TRUNC | O_WRONLY, (DEF_MODE) & ~(DEF_UMASK));
    if (outfd < 0) {
        perror(outfile);
        exit(1);
    }
    dup2(outfd, STDOUT_FILENO);
    close(outfd);
}

/**
 * @brief Main entry of the shell
 *
 * It set the stderr to stdout so that the driver will get all output, parse
 * command line such as h,v,p; Install the signal handler, create environment,
 * initilize the job list and main loop for eval since this is a long running
 * process, it will all quit when called or aborted. it also handles interactive
 * command input and execution of commands, along with job control.
 *
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv(strdup("MY_ENV=42")) < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief evaluate the command line argument and execute the inputs
 *
 * This function parses the command line input, handles built-in commands such
 * as quit, jobs, bg, fg, and executes external commands. It also sets up signal
 * blocking and handling as necessary for job list control and implements I/O
 * redirection when specified in the command.
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;

    // Parse command line
    parse_result = parseline(cmdline, &token);
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    sigset_t mask, prev_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);

    // Implement builtin commands here.
    if (token.builtin == BUILTIN_QUIT) {
        // handle builtin command
        // sio_printf("Built in quit recognized, exiting the shell.\n");
        exit(0);
    } else if (token.builtin == BUILTIN_BG || token.builtin == BUILTIN_FG) {
        sigprocmask(SIG_BLOCK, &mask,
                    &prev_mask); // block all signals before accessing joblits
        bool pid_cmd = false;
        bool cmd_number = false;
        if (token.argc > 1) {
            jid_t job_id = get_jid(token, &pid_cmd, &cmd_number);

            if (!job_exists(job_id) || job_id == 0) {
                print_error_builtin(token, cmd_number, pid_cmd);
            } else {
                resume_job(job_id, token, prev_mask);
            }

        } else {
            sio_printf("%s command requires PID or %%jobid argument\n",
                       token.argv[0]);
        }
        sigprocmask(SIG_SETMASK, &prev_mask, NULL); // unblock signal
    } else if (token.builtin == BUILTIN_JOBS) {
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        // handles jobs redirection in child process
        if (token.outfile != NULL) {
            if ((pid = fork()) == 0) {
                output_redirection(token.outfile);
                list_jobs(STDOUT_FILENO);
                exit(0);
            } else if (pid > 0) {
                int status;
                // wait the child to finish
                waitpid(pid, &status, 0);
            } else {
                perror("fork");
            }
        } else {
            list_jobs(STDOUT_FILENO);
        }
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    } else if (token.builtin == BUILTIN_NONE) {
        // handle external command
        // Block signals before fork
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);

        /* figure 8.24 csapp*/
        if ((pid = fork()) == 0) { // child process
            sigprocmask(SIG_SETMASK, &prev_mask,
                        NULL); // unblock child process signals
            setpgid(0, 0);     // in foreground process group

            if (token.infile != NULL) {
                input_redirection(token.infile);
            }

            if (token.outfile != NULL) {
                output_redirection(token.outfile);
            }

            if (execve(token.argv[0], token.argv, environ) < 0) {
                if (errno == EACCES) {
                    sio_printf("%s: Permission denied\n", token.argv[0]);
                } else if (errno == ENOENT) {
                    sio_printf("%s: No such file or directory\n",
                               token.argv[0]);
                }
                exit(1); // child process, don't effect parent to exit
            }
        }

        /* Parent waits for foreground job to terminate */
        jid_t job_id = 0;
        if (parse_result == PARSELINE_FG) {
            sigprocmask(SIG_BLOCK, &mask, NULL);
            job_id = add_job(pid, FG, cmdline);
            while (fg_job() != 0) {
                sigsuspend(&prev_mask);
            }
            sigprocmask(SIG_SETMASK, &prev_mask, NULL); // optionally unblock

        } else if (parse_result == PARSELINE_BG) { // background job handler
            sigprocmask(SIG_BLOCK, &mask, NULL);
            job_id = add_job(pid, BG, cmdline);
            sio_printf("[%d] (%d) %s\n", job_id, pid, cmdline);
        }

        // Unblock all signals
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    }
    return;
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief handles SIGCHLD signal
 *
 * This handler is called when SIGCHLD signal is received, meaning a child
 * process has stopped or terminated. The handler reaps any child process that
 * has been stopped or terminated. It deletes the job from joblist if terminated
 * or change the state in job list if stopped.
 */
void sigchld_handler(int sig) {
    int olderrno = errno; // save the current errno
    int status;
    sigset_t mask, prev;
    sigfillset(&mask);
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        sigprocmask(SIG_BLOCK, &mask, &prev);
        if (WIFEXITED(status)) { // child terminated normally
            delete_job(job_from_pid(
                pid)); // delete the child from job list if terminated
        } else if (WIFSTOPPED(status)) { // child is stopped
            sio_printf("Job [%d] (%d) stopped by signal %d\n",
                       job_from_pid(pid), pid, WSTOPSIG(status));
            job_set_state(job_from_pid(pid), ST);
        } else if (WIFSIGNALED(status)) { // child is terminated
            sio_printf("Job [%d] (%d) terminated by signal %d\n",
                       job_from_pid(pid), pid, WTERMSIG(status));
            delete_job(job_from_pid(pid));
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);
    }
    errno = olderrno; // restore the old errno
}

/**
 * @brief Handles SIGINT (ctrl + c)
 *
 * This handler is called when the shell receives a SIGINT signal, it will catch
 * the signal and forward to the entire process group that contains the
 * foreground job.
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    sigset_t mask, prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    jid_t job_id = fg_job();
    if (job_id != 0) {
        pid = job_get_pid(job_id);
        sigprocmask(SIG_SETMASK, &prev, NULL);
        kill(-pid, SIGINT); // pid < 0, kills every process in pg
    }
    errno = olderrno;
}

/**
 * @brief Handles SIGTSTP (ctrl + z)
 *
 * This function is called when the shell receives a SIGTSTP signal, it is
 * similar to SIGINT handler, except it will be able to continue after resume
 * after receive a SIGCONT signal
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    sigset_t mask, prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    jid_t job_id = fg_job();
    if (job_id != 0) {
        pid = job_get_pid(job_id);
        sigprocmask(SIG_SETMASK, &prev, NULL);
        kill(-pid, SIGTSTP); // pid < 0, kills every process in pg
    }
    errno = olderrno;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
