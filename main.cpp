#include <iostream>
#include <array>
#include <vector>
#include <string>
#include <regex>
#include <cstdlib>

#include <boost/filesystem.hpp>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>

#include <libcgroup.h>

#define STACK_SIZE 1024 * 1024
#define NOBODY_UID 65534

namespace fs = boost::filesystem;
namespace bs = boost::system;

struct exe_opts {
    const fs::path &sandbox;
    const fs::path &bin_path;
    const std::vector<char *> &args;
    const std::vector<char *> &env;
};

void fatal(const std::string &message) {
    std::cerr << message << std::endl;
    exit(EXIT_FAILURE);
}

void fatal_errno(const std::string &message) {
    std::cerr << message << ": " << strerror(errno) << std::endl;
    exit(EXIT_FAILURE);
}

void fatal_cgroup(const std::string &message) {
    std::cerr << message << ": " << cgroup_strerror(cgroup_get_last_errno()) << std::endl;
    exit(EXIT_FAILURE);
}

void init_dirs(const fs::path &sandbox) {
    std::array<std::string, 5> dirs = {"dev", "etc", "proc", "root", "tmp"};

    bs::error_code ec;
    for (auto &dir:dirs) {
        fs::create_directories(sandbox / dir, ec);
        if (ec.value() != bs::errc::success)
            fatal("cannot create system dir: " + ec.message());
    }
}

void libs_deps(fs::path &bin, std::vector<std::string> &res) {
    std::array<char, 256> buffer{};

    std::string out_buf;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(
            (std::string("/usr/bin/ldd ") + bin.string()).c_str(), "r"), pclose);
    if (!pipe) {
        fatal("cannot get libraries dependencies");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        out_buf += buffer.data();
    }

    std::regex e(R"((?:.+?\s+=>)?\s+(/.+?)\s+\(.+?\))");
    std::smatch m;

    while (std::regex_search(out_buf, m, e)) {
        if (m.length() < 2)
            continue;
        res.push_back(m[1]);
        out_buf = m.suffix().str();
    }
}

void add_file(const fs::path &sandbox, const fs::path &src, const fs::path &dst, bool with_deps) {
    auto sbox_path = sandbox / dst;

    bs::error_code ec;

    fs::create_directories(sbox_path.parent_path(), ec);
    if (ec.value() != bs::errc::success)
        fatal("cannot create adding file directory: " + ec.message());

    fs::create_hard_link(src, sbox_path, ec);
    if (ec != bs::errc::success && ec != bs::errc::file_exists)
        fatal("cannot create adding file hardlink: " + ec.message());

    if (with_deps) {
        std::vector<std::string> libs;
        libs_deps(sbox_path, libs);

        for (auto &l:libs) {
            auto sbox_lib = sandbox / l;
            fs::create_directories(sbox_lib.parent_path(), ec);
            if (ec.value() != bs::errc::success)
                fatal("cannot create directory for shared link: " + ec.message());

            fs::path real_path = l;
            if (fs::is_symlink(l)) {
                auto target = fs::read_symlink(l, ec);
                if (ec.value() != bs::errc::success)
                    fatal("cannot read symlink shared link: " + ec.message());

                if (target.has_root_path())
                    real_path = target;
                else
                    real_path = fs::path(l).parent_path() / target;
            }

            fs::create_hard_link(real_path, sbox_lib, ec);
            if (ec != bs::errc::success && ec != bs::errc::file_exists)
                fatal("cannot create hardlink for shared library: " + ec.message());
        }
    }
}

cgroup *create_cgroup(const std::string &name, uint64_t mem_limit) {
    if (cgroup_init())
        fatal_cgroup("cannot init cgroup");

    auto cgroup = cgroup_new_cgroup(name.c_str());

    if (mem_limit) {
        auto mem_ctrl = cgroup_add_controller(cgroup, "memory");
        if (cgroup_set_value_uint64(mem_ctrl, "memory.limit_in_bytes", mem_limit))
            fatal_cgroup("cannot set memory limit");
    }

    if (cgroup_create_cgroup(cgroup, 0))
        fatal_cgroup("cannot create cgroup");

    return cgroup;
}

static int _execute(void *arg) {
    auto *opts = static_cast<exe_opts *>(arg);

    if (chroot(opts->sandbox.c_str()))
        fatal_errno("cannot chroot");

    if (mount("udev", "/dev", "devtmpfs", 0, nullptr))
        if (errno != EBUSY)
            fatal_errno("cannot mount /dev");

    if (mount("proc", "/proc", "proc", 0, nullptr))
        if (errno != EBUSY)
            fatal_errno("cannot mount /proc");

    if (chdir("/root"))
        fatal_errno("cannot chdir");

    if (setgid(NOBODY_UID))
        fatal_errno("cannot set GID");

    if (setuid(NOBODY_UID))
        fatal_errno("cannot set UID");

    execve(opts->bin_path.c_str(), opts->args.data(), opts->env.data());
    fatal("cannot run file: " + std::string(strerror(errno)));

    return EXIT_SUCCESS;
}

void execute(const fs::path &sandbox, const fs::path &bin, const std::vector<char *> &args,
             const std::vector<char *> &env, const std::string &cgroup_name, const uint64_t mem_limit) {

    if (mem_limit && cgroup_name.empty())
        fatal("cannot set memory limit without cgroup name");

    exe_opts opts{sandbox, bin, args, env};

    cgroup *cgroup = nullptr;
    if (!cgroup_name.empty()) {
        cgroup = create_cgroup(cgroup_name, mem_limit);
        if (cgroup_attach_task(cgroup))
            fatal_cgroup("cannot attach process to cgroup");
    }

    char *stack, *stackTop;
    stack = static_cast<char *>(malloc(STACK_SIZE));
    if (stack == nullptr)
        fatal("cannot allocate stack");

    stackTop = stack + STACK_SIZE;

    auto pid = clone(_execute, stackTop,
                     CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET | SIGCHLD, &opts);
    if (pid == -1)
        fatal("cannot clone");

    waitpid(pid, nullptr, 0);

    if (cgroup != nullptr) {
        if (cgroup_delete_cgroup(cgroup, 0))
            fatal_cgroup("cannot delete cgroup");

        cgroup_free(&cgroup);
    }

    if (umount2((sandbox / "/dev").c_str(), MNT_FORCE))
        fatal_errno("cannot umount /dev");

    if (umount2((sandbox / "/proc").c_str(), MNT_FORCE))
        fatal_errno("cannot umount /proc");

    bs::error_code ec;
    fs::remove_all(sandbox, ec);
    if (ec.value() != bs::errc::success)
        fatal("cannot remove sanbox: " + ec.message());
}

void print_usage() {
    std::cout << R"(Usage:
    sandbox <sandbox path> [args] -- <cmd to execute> [cmd args]
args:
    --add_file <src host path> <dst sandbox path>
        Copy file from host system to sandbox

    --add_elf_file <src host path> <dst sandbox path>
        Copy ELF file from host system to sandbox with needed libraries

    --env <value>
        Environ variables

    --cgroup <name>
        Run process in cgroup1

    --mem_limit 0
        Limit memory for process
)" << std::endl;

    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (getuid() != 0 && geteuid() != 0)
        fatal("required root privileges");

    if (argc < 2 || strncmp(argv[1], "--", 2) == 0)
        print_usage();

    fs::path sandbox = argv[1];
    init_dirs(sandbox);

    fs::path cmd;
    std::string cgroup;
    uint64_t mem_limit = 0;
    std::vector<char *> cmd_args = {nullptr}; // reserved for cmd path
    std::vector<char *> cmd_env;

    auto i = 2;
    while (i < argc) {
        if (strcmp(argv[i], "--") == 0) {
            if (i + 1 > argc)
                print_usage();
            cmd = argv[i + 1];

            for (i = i + 2; i < argc; i++)
                cmd_args.emplace_back(argv[i]);

            break;
        } else if (strcmp(argv[i], "--add_file") == 0 || strcmp(argv[i], "--add_elf_file") == 0) {
            if (i + 3 > argc || strncmp(argv[i + 1], "--", 2) == 0 || strncmp(argv[i + 2], "--", 2) == 0)
                print_usage();

            add_file(sandbox, argv[i + 1], argv[i + 2], strcmp(argv[i], "--add_elf_file") == 0);

            i += 3;

        } else if (strcmp(argv[i], "--env") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            cmd_env.push_back(argv[i + 1]);

            i += 2;
        } else if (strcmp(argv[i], "--cgroup") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            cgroup = argv[i + 1];

            i += 2;

        } else if (strcmp(argv[i], "--mem_limit") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            mem_limit = std::strtoll(argv[i + 1], nullptr, 10);

            i += 2;

        } else {
            print_usage();
        }
    }

    cmd_args[0] = const_cast<char *>(cmd.c_str());
    cmd_args.push_back(nullptr);
    cmd_env.push_back(nullptr);

    execute(sandbox, cmd, cmd_args, cmd_env, cgroup, mem_limit);

    return EXIT_SUCCESS;
}