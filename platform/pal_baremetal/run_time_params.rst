EL3-Driven Module Selection
===========================

Overview
--------

In addition to build-time and runtime module selection, ACS supports
a simple mechanism for **EL3 firmware** to tell ACS which modules
and/or tests to run.

This is useful when:

* EL3 wants to enforce a policy (for example, only PCIe tests).
* You want to avoid command-line/runtime configuration in NS-EL2.
* You need per-boot, firmware-controlled selection.

The mechanism is:

* EL3 passes a pointer to a parameter structure in a shared memory region.
* EL3 also passes a magic value to indicate that parameters are valid.
* ACS reads the structure once at boot and overrides its internal tables.

Register Convention
-------------------

When jumping from EL3 to the ACS entry point (``acs_entry``):

* **X19** must contain the magic value ``ACS_EL3_PARAM_MAGIC``.
* **X20** must contain the address of an ``acs_el3_params`` structure.

If X19 does **not** match ``ACS_EL3_PARAM_MAGIC``, ACS will **ignore X20**
and run with its normal configuration (command-line / default modules).

Parameter Structure
-------------------

The structure layout is defined in ``acs_el3_param.h`` as:

.. code-block:: c

   #define ACS_EL3_PARAM_MAGIC  0x414353454C335031ULL  /* 'ACSEL3P1' */

typedef struct {
  uint64_t version;

  /* Optional: test selection override */
  uint64_t test_array_addr;      /* uint32_t[] of test IDs (can be 0) */
  uint64_t test_array_count;     /* number of entries in test_array_addr */

  /* Optional: module selection override */
  uint64_t module_array_addr;    /* uint32_t[] of module IDs (can be 0) */
  uint64_t module_array_count;   /* number of entries in module_array_addr */

  /* Optional: Tests to skip (introduced in version 0x2) */
  uint64_t skip_test_array_addr;  /* uint32_t[] of test IDs to skip (can be 0) */
  uint64_t skip_test_array_count; /* number of entries in skip_test_array_addr */

  /* Optional: Modules to skip (introduced in version 0x3) */
  uint64_t skip_module_array_addr;  /* uint32_t[] of module IDs to skip (can be 0) */
  uint64_t skip_module_array_count; /* number of entries in skip_module_array_addr */
} acs_el3_params;

Notes:

* The structure must live in memory that NS-EL2 / ACS can read.
* Only the **address** of the structure is passed in X20.
* ``version`` is used by ACS to check compatibility (currently 0 or 1).
* Any combination of tests, modules, or skip list may be provided.

Module and Rule IDs
-------------------

Module IDs are the **existing ENUMs**. For example:

.. code-block:: c

#define DA_MODULE        "da"
#define DPT_MODULE       "dpt"
#define GIC_MODULE       "gic"
#define LEGACY_MODULE    "legacy"
#define MEC_MODULE       "mec"
#define RME_MODULE       "rme"
#define SMMU_MODULE      "smmu"
#define CXL_MODULE       "cxl"
#define CDA_MODULE       "cda"
#define TDISP_MODULE     "tdisp"


You can pass either:

* the **Module Id** (for example ``DA_MODULE, DPT_MODULE``), or
* any Rule ID inside that module’s range.

ACS will map each ID to an internal module bitmask and then derive the
runtime mask (``g_enabled_modules``) as usual.

What ACS Does Internally
------------------------

At boot, ACS:

1. Saves X19 and X20 into globals (``g_el3_param_magic``, ``g_el3_param_addr``)
   in ``RmeBootEntry.S``.
2. In ``ShellAppMainrme()``, calls a helper
   (``acs_apply_el3_params()``) which:
   * Checks that ``g_el3_param_magic == ACS_EL3_PARAM_MAGIC``.
   * Checks that the parameter structure address is non-zero.
   * Checks that ``version`` is acceptable.
   * If valid:
     - Overrides ``g_rule_list`` / ``g_rule_count`` if test override is given.
     - Overrides ``g_execute_modules`` / ``g_num_modules`` if module override is given.
     - Overrides ``g_skip_rule_list`` / ``g_skip_rule_count`` if a skip list is given.
3. Uses the (possibly overridden) ``g_execute_modules`` / ``g_num_modules`` to
   compute ``g_enabled_modules``, and then:
   * Creates only the required information tables.
   * Executes only the enabled modules.

If X19 does not contain ``ACS_EL3_PARAM_MAGIC`` or the structure is invalid,
ACS falls back to its usual behavior (no EL3 override).

Simple EL3 Example
------------------

Below is a minimal example showing how EL3 can force ACS to run only
DA modules while skipping a specific test.

.. code-block:: c

   #include "acs_el3_param.h"

   static uint32_t modules_to_run[] = {
     DA_MODULE,
   };

   static char8_t *el3_skip_test_list[] = {
       "da_attribute_rmeda_ctl_registers",
   };

   static acs_el3_params acs_params __attribute__((aligned(64))) = {
       .version              = 1,
       .rule_array_addr      = 0,     /* no rule overrides */
       .rule_array_count     = 0,
       .module_array_addr    = (uint64_t)modules_to_run,
       .module_array_count   = sizeof(modules_to_run) / sizeof(uint32_t),
       .skip_rule_array_addr = (uint64_t)(uintptr_t)el3_skip_test_list,
       .skip_rule_array_count= sizeof(el3_skip_test_list)/sizeof(el3_skip_test_list[0])
   };

   void jump_to_acs(uint64_t acs_entry_pa)
   {
       register uint64_t x19 __asm__("x19") = ACS_EL3_PARAM_MAGIC;
       register uint64_t x20 __asm__("x20") = (uint64_t)&acs_params;

       /* Program the NS-EL2 entry point and perform the world switch here.
        * The exact code depends on your firmware (TF-A, custom EL3, etc.).
        *
        * After the switch, execution will start at acs_entry_pa
        * (acs_entry) with:
        *   x19 = ACS_EL3_PARAM_MAGIC
        *   x20 = &acs_params
        */
   }

If you want ACS to **ignore** EL3 parameters and run normally,
do **not** set X19 to the magic value (for example, leave X19 = 0).

Requirements for Partners
-------------------------

* ``acs_el3_params`` must live in memory that NS-EL2 can read.
* X19 must be set to ``ACS_EL3_PARAM_MAGIC`` to enable the override.
* X20 must hold the address of a valid ``acs_el3_params`` structure.
* The module IDs in ``module_array_addr`` must be valid ACS Rule IDs
* If ``module_array_count == 0``, ACS will not override modules and will
  behave as if no module list was provided.
* If ``skip_rule_array_count == 0``, ACS falls back to its default skip list.

This interface allows platform firmware to control ACS execution in a
simple, well-defined way without changing the ACS build or command-line
configuration.


## 📄 License

Distributed under [Apache v2.0 License](https://www.apache.org/licenses/LICENSE-2.0).
© 2025-2026, Arm Limited and Contributors.
