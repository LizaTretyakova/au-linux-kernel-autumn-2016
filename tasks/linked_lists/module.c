#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/errno.h>

#include "stack.h"
#include "assert.h"

void clear_process_list(struct list_head *stack)
{
    stack_entry_t* cur;

    while (!stack_empty(stack))
    {
        cur = stack_pop(stack);
        kfree(STACK_ENTRY_DATA(cur, char*));
        delete_stack_entry(cur);
    }
}

#define CHECK_NOT_NULL(ptr, stack_top, ret) \
    if (!ptr) \
    { \
        clear_process_list(&stack_top); \
        ret = -ENOMEM; \
        break; \
    }


static int __init test_stack(void)
{
    int ret = 0;
    LIST_HEAD(data_stack);
    stack_entry_t *tos = NULL;
    const char *tos_data = NULL;
    const char* test_data[] = { "1", "2", "3", "4" };
    long i = 0;

    pr_alert("Testing basic stack");

    for (i = 0; i != ARRAY_SIZE(test_data); ++i) {
        tos = create_stack_entry((void*)test_data[i]);
        if (!tos) {
            ret = -ENOMEM;
            break;
        }
        stack_push(&data_stack, tos);
    }

    for (i = ARRAY_SIZE(test_data) - 1; i >= 0; --i) {
        tos = stack_pop(&data_stack);
        tos_data = STACK_ENTRY_DATA(tos, const char*);
        delete_stack_entry(tos);
        printk(KERN_ALERT "!%s! == !%s!\n", tos_data, test_data[i]);
        assert(!strcmp(tos_data, test_data[i]));
    }

    assert(stack_empty(&data_stack));
    if (ret == 0)
        pr_alert("Test success!\n");

    return ret;
}

static int __init print_processes_backwards(void)
{
    int ret = 0;
    LIST_HEAD(data_stack);
    stack_entry_t *cur = NULL;
    struct task_struct *p;
    char* name;

    for_each_process(p)
    {
        // Get the name.
        char* data = kmalloc(sizeof(p->comm), GFP_KERNEL);
        CHECK_NOT_NULL(data, data_stack, ret)

        CHECK_NOT_NULL(get_task_comm(data, p), data_stack, ret)

        // Put to stack.
        cur = create_stack_entry(data);
        CHECK_NOT_NULL(cur, data_stack, ret)

        stack_push(&data_stack, cur);
    }

    printk(KERN_ALERT "Hopefully now here appears the list of files in reversed order");
    while (!stack_empty(&data_stack))
    {
        cur = stack_pop(&data_stack);
        name = STACK_ENTRY_DATA(cur, char*);
        delete_stack_entry(cur);
        printk(KERN_ALERT "Yet another file: %s\n", name);
        kfree(name);
    }

    return ret;
}

static int __init ll_init(void)
{
    int ret = 0;
    printk(KERN_ALERT "Hello, linked_lists\n");

    ret = test_stack();
    if (ret)
        goto error;

    ret = print_processes_backwards();

error:
    return ret;
}

static void __exit ll_exit(void)
{
    printk(KERN_ALERT "Goodbye, linked_lists!\n");
}

module_init(ll_init);
module_exit(ll_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linked list exercise module");
MODULE_AUTHOR("Kernel hacker!");
