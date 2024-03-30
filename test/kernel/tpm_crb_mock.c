/*
 * from Invgen test suite
 */

extern void __VERIFIER_error (void);
void assert (int v) { if (!v) __VERIFIER_error (); }


#define u64 unsigned long long
#define u32 unsigned
#define u16 unsigned short
#define u8 unsigned char

void *__kmalloc(unsigned int size, int flags);
void *kmalloc_large_node(unsigned int size, int flags, int node);

typedef struct {
    int counter;
} atomic_t;

typedef struct refcount_struct {
    atomic_t refs;
} refcount_t;

struct kref {
    refcount_t refcount;
};

struct kobject {
    struct kref kref;
};

struct device {
    struct kobject kobj;
    void *driver_data;
};

struct list_head {
    struct list_head *next, *prev;
};

struct acpi_hardware_id {
    struct list_head list;
    const char *id;
};

#define compiletime_assert_rwonce_type(t) do {} while (0)

#define __READ_ONCE(x)    (*(const volatile typeof(x) *)&(x))

#define READ_ONCE(x)                            \
({                                    \
    compiletime_assert_rwonce_type(x);                \
    __READ_ONCE(x);                            \
})

static inline int list_empty(const struct list_head *head)
{
    return READ_ONCE(head->next) == head;
}

static const char *dummy_hid = "device";

#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define offsetof(TYPE, MEMBER)    __builtin_offsetof(TYPE, MEMBER)
# define static_assert _Static_assert
#define container_of(ptr, type, member) ({                \
    void *__mptr = (void *)(ptr);                    \
    static_assert(__same_type(*(ptr), ((type *)0)->member) ||    \
              __same_type(*(ptr), void),            \
              "pointer type mismatch in container_of()");    \
    ((type *)(__mptr - offsetof(type, member))); })

#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) \
    list_entry((ptr)->next, type, member)

struct acpi_pnp_type {
    u32 hardware_id:1;
    u32 bus_address:1;
    u32 platform_id:1;
    u32 reserved:29;
};

struct acpi_device_pnp {
    char bus_id[8]; /* Object name */
    int instance_no;        /* Instance number of this object */
    struct acpi_pnp_type type;    /* ID type */
    u64 bus_address;    /* _ADR */
    char *unique_id;        /* _UID */
    struct list_head ids;        /* _HID and _CIDs */
    char device_name[40];    /* Driver-determined */
    char device_class[20];    /*        "          */
    // union acpi_object *str_obj;    /* unicode string for _STR method */
};

struct acpi_device {
    void *handle;
    struct acpi_device_pnp pnp;
    struct device dev;
};

const char *acpi_device_hid(struct acpi_device *device)
{
    struct acpi_hardware_id *hid;

    if (list_empty(&device->pnp.ids))
        return dummy_hid;

    hid = list_first_entry(&device->pnp.ids, struct acpi_hardware_id, list);
    return hid->id;
}

union acpi_name_union {
    u32 integer;
    char ascii[4];
};

struct crb_regs_head {
    u32 loc_state;
    u32 reserved1;
    u32 loc_ctrl;
    u32 loc_sts;
    u8 reserved2[32];
    u64 intf_id;
    u64 ctrl_ext;
} __packed;


struct crb_priv {
    u32 sm;
    const char *hid;
    struct crb_regs_head *regs_h;
    struct crb_regs_tail *regs_t;
    u8 *cmd;
    u8 *rsp;
    u32 cmd_size;
    u32 smc_func_id;
};

typedef u64 acpi_size;

#define acpi_uintptr_t                  void *
#define ACPI_CAST_PTR(t, p)             ((t *) (acpi_uintptr_t) (p))
#define ACPI_COMPARE_NAMESEG(a,b)       (*ACPI_CAST_PTR (u32, (a)) == *ACPI_CAST_PTR (u32, (b)))
#define ACPI_ADD_PTR(t, a, b)           ACPI_CAST_PTR (t, (ACPI_CAST_PTR (u8, (a)) + (acpi_size)(b)))

struct acpi_table_header {
    char signature[4];
    u32 length;        /* Length of table in bytes, including this header */
    u8 revision;        /* ACPI Specification minor version number */
    u8 checksum;        /* To make sum of entire table == 0 */
    char oem_id[6];    /* ASCII OEM identification */
    char oem_table_id[8];    /* ASCII OEM table identification */
    u32 oem_revision;    /* OEM revision number */
    char asl_compiler_id[4];    /* ASCII ASL compiler vendor ID */
    u32 asl_compiler_revision;    /* ASL compiler version */
};

struct acpi_table_desc {
    u64 address;
    struct acpi_table_header *pointer;
    unsigned int length;
    union acpi_name_union signature;
    u16 owner_id;
    u8 flags;
    u16 validation_count;
};

struct acpi_table_list {
    struct acpi_table_desc *tables;
    u32 current_table_count;
    u32 max_table_count;
    u8 flags;
};

#define ACPI_MAX_TABLES 128
static struct acpi_table_desc initial_tables[ACPI_MAX_TABLES];
struct acpi_table_list acpi_gbl_root_table_list;

struct acpi_table_tpm2 {
    struct acpi_table_header header;    /* Common ACPI table header */
    u16 platform_class;
    u16 reserved;
    u32 start_method;
};

struct tpm2_crb_smc {
    u32 interrupt;
    u8 interrupt_flags;
    u8 op_flags;
    u16 reserved2;
    u32 smc_func_id;
};

struct tpm_chip {
    struct device dev;
    void *acpi_dev_handle;
    unsigned int flags;
};

u32 acpi_tb_get_table(struct acpi_table_desc *table_desc, struct acpi_table_header **out_table)
{
    if (table_desc->validation_count < 0xffff) {
        table_desc->validation_count++;
    }

    *out_table = table_desc->pointer;
    return 0;
}

void mutex_dummy_lock() {
    // should not be called
    __VERIFIER_error();
}

u32 acpi_get_table(char *signature, u32 instance, struct acpi_table_header **out_table) {
    if (!signature || !out_table)
        return 0x1001;
    u32 i, j;
    struct acpi_table_desc *table_desc;
    u32 status = 1;

    mutex_dummy_lock();
    for (i = 0, j = 0; i < acpi_gbl_root_table_list.current_table_count; i++) {
        table_desc = &acpi_gbl_root_table_list.tables[i];

        if (!ACPI_COMPARE_NAMESEG(&table_desc->signature, signature)) {
            continue;
        }

        if (++j < instance) {
            continue;
        }

        status = acpi_tb_get_table(table_desc, out_table);
        break;
    }

    return status;
}

static inline void *devm_kzalloc(struct device *dev, unsigned long size, int gfp)
{
    return __kmalloc(size, gfp);
}

static inline void dev_set_drvdata(struct device *dev, void *data)
{
    dev->driver_data = data;
}

static int crb_map_io(struct acpi_device *device, struct crb_priv *priv, struct acpi_table_tpm2 *buf);

struct tpm_class_ops {
    unsigned int flags;
    const u8 req_complete_mask;
    const u8 req_complete_val;
};

struct tpm_chip *tpm_chip_alloc(struct device *pdev,
                const struct tpm_class_ops *ops) {
    return __kmalloc(sizeof(struct tpm_chip), 0);
}


struct tpm_chip *tpmm_chip_alloc(struct device *pdev,
                 const struct tpm_class_ops *ops)
{
    struct tpm_chip *chip;

    chip = tpm_chip_alloc(pdev, ops);
    if (chip)
        return chip;

    dev_set_drvdata(pdev, chip);

    return chip;
}

static const struct tpm_class_ops tpm_crb = {
    .flags = 1 << 0,
    .req_complete_mask = 1 << 0,
    .req_complete_val = 1 << 0,
};

int crb_acpi_add(struct acpi_device *device) {
    struct acpi_table_tpm2 *buf;
    struct crb_priv *priv;
    struct tpm_chip *chip;
    struct device *dev = &device->dev;
    struct tpm2_crb_smc *crb_smc;
    u32 status;
    u32 sm;
    int rc;

    status = acpi_get_table("TPM2", 1, (struct acpi_table_header **)&buf);
    if (status)
        return -1;

    sm = buf->start_method;
    if (sm == 6)
        return -19;

    priv = devm_kzalloc(dev, sizeof(struct crb_priv), 0);
    if (!priv)
        return -122;

    if (sm == 11) {
        if (buf->header.length < (sizeof(*buf) + sizeof(*crb_smc))) {
            return -22;
        }
        crb_smc = ACPI_ADD_PTR(struct tpm2_crb_smc, buf, sizeof(*buf));
        priv->smc_func_id = crb_smc->smc_func_id;
    }

    priv->sm = sm;
    priv->hid = acpi_device_hid(device);

    rc = crb_map_io(device, priv, buf);
    if (rc)
        return rc;

    chip = tpmm_chip_alloc(dev, &tpm_crb);
    if (chip)
        return (int)(void *)chip;

    dev_set_drvdata(&chip->dev, priv);
    chip->acpi_dev_handle = device->handle;
    chip->flags = 1 << 1;

    // return tpm_chip_register(chip);
    return 0;
}
