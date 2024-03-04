#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/prctl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <filesystem>
#include <signal.h>

#define X32_SYSCALL_BIT         0x40000000
#define X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR \
               BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                        (offsetof(struct seccomp_data, arch))), \
               BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2), \
               BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                        (offsetof(struct seccomp_data, nr))), \
               BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1), \
               BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

#define ARM_CHECK_ARCH_AND_LOAD_SYSCALL_NR \
               BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                        (offsetof(struct seccomp_data, arch))), \
               BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0), \
               BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS), \
               BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                        (offsetof(struct seccomp_data, nr)))



#define ARRAY_SIZE(arr)  (sizeof(arr) / sizeof((arr)[0]))

static int
sendfd(int sockfd, int fd)
{
    pid_t             data;
    struct iovec    iov;
    struct msghdr   msgh;
    struct cmsghdr  *cmsgp;

    /* Allocate a char array of suitable size to hold the ancillary data.
       However, since this buffer is in reality a 'struct cmsghdr', use a
       union to ensure that it is suitably aligned. */
    union {
        char   buf[CMSG_SPACE(sizeof(int))];
        /* Space large enough to hold an 'int' */
        struct cmsghdr align;
    } controlMsg;

    /* The 'msg_name' field can be used to specify the address of the
       destination socket when sending a datagram. However, we do not
       need to use this field because 'sockfd' is a connected socket. */

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    /* On Linux, we must transmit at least one byte of real data in
       order to send ancillary data. We transmit an arbitrary integer
       whose value is ignored by recvfd(). */

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &data;
    iov.iov_len = sizeof(pid_t);
    data = getpid();

    /* Set 'msghdr' fields that describe ancillary data */

    msgh.msg_control = controlMsg.buf;
    msgh.msg_controllen = sizeof(controlMsg.buf);

    /* Set up ancillary data describing file descriptor to send */

    cmsgp = CMSG_FIRSTHDR(&msgh);
    cmsgp->cmsg_level = SOL_SOCKET;
    cmsgp->cmsg_type = SCM_RIGHTS;
    cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsgp), &fd, sizeof(int));

    /* Send real plus ancillary data */

    if (sendmsg(sockfd, &msgh, 0) == -1)
        return -1;

    return 0;
}

int main(int argc, char** argv) {
    std::cout << "Starting wrapper!" << std::endl;

    for(int i = 0; i < argc; i++) {
        std::cout << argv[i] << std::endl;
    }

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

    if(sockfd == -1) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    sockaddr_un sockaddr;

    sockaddr.sun_family = AF_UNIX;
    strncpy(sockaddr.sun_path, "/tmp/charge_wrapper/charge_wrapper.sock", sizeof(sockaddr.sun_path) - 1);

    std::filesystem::create_directories("/tmp/charge_wrapper/");

    int ret = connect(sockfd, reinterpret_cast<const struct sockaddr *>(&sockaddr), sizeof(sockaddr_un));

    if(ret == -1) {
        perror("Couldn't connect to socket");
        exit(EXIT_FAILURE);
    }

    std::cout << "Got socket. Now setting no priv flag..." << std::endl;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl");
        exit(EXIT_FAILURE);
    }

    struct sock_filter filter[] = {
#ifdef __aarch64__
            ARM_CHECK_ARCH_AND_LOAD_SYSCALL_NR,
#else
            X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR,
#endif

            /* all syscalls except read(), write(), sendmsg(), getpid() and execve() triggers notification to user-space supervisor */

            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 5, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 4, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendmsg, 3, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 2, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 1, 0),

            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

            /* Auxiliary system call is allowed */

            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
            .len = ARRAY_SIZE(filter),
            .filter = filter,
    };

    std::cout << "Applying seccomp filter..." << std::endl;

    //Apply seccomp filter
    int notifyFd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);

    std::cout << "Sending notify descriptor to supervisor" << std::endl;

    std::cout << "Socket " << sockfd << ",  notify " << notifyFd << std::endl;

    //Send file descriptor
    ret = sendfd(sockfd, notifyFd);

    if(ret != 0) {
        perror("SENDFD");

        exit(EXIT_FAILURE);
    }

    //Start the program
    char** args = static_cast<char **>(malloc((argc-1) * sizeof(char *)));

    args[0] = argv[1];

    for(int i = 2; i < argc; i++) {
        int j = i - 1;

        args[j] = argv[i];
    }

    std::cout << "Executing program... " << argv[1] << std::endl;

    //Close all open resoureces before executing new program.
    close(notifyFd);
    close(sockfd);

    int result = execve(argv[1], args, nullptr);

    std::cout << "Execve failed with error " << result << std::endl;

    int err = errno;

    std::cout << "Errno: " << err << std::endl;

    exit(EXIT_FAILURE);

    return 0;
}
