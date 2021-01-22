#include <openenclave/enclave.h>
#include "ebpf_verifier.hpp"
#include <openenclave/enclave.h>
#include "Verifier.h"
#include <sstream>
#include <sys/mount.h>

int setup()
{
    oe_result_t result;

    /* Load the host file system module. */
    if ((result = oe_load_module_host_file_system()) != OE_OK)
        return -1;

    /* Mount the host file system on the root directory. */
    if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0)
        return -1;

    return 0;
}

int Verify(const char* filename, const char* sectionname)
{
    int err = setup();
    if (err != 0) {
        return err;
    }

    auto raw_progs = read_elf(filename, sectionname, create_map_crab, nullptr);
    if (raw_progs.size() != 1) {
        return 1; // Error
    }
    raw_program raw_prog = raw_progs.back();
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    if (!std::holds_alternative<InstructionSeq>(prog_or_error)) {
        return 1; // Error;
    }
    auto& prog = std::get<InstructionSeq>(prog_or_error);
    cfg_t cfg = prepare_cfg(prog, raw_prog.info, true);
    bool res = run_ebpf_analysis(std::cout, cfg, raw_prog.info, nullptr);
    if (!res) {
        return 1; // Error;
    }
    return 0; // Success.
}