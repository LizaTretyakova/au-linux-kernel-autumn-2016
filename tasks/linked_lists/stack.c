#include "stack.h"

#include "assert.h"
#include <linux/slab.h>
#include <linux/gfp.h>

stack_entry_t* create_stack_entry(void *data)
{
    stack_entry_t* result = kmalloc(sizeof(stack_entry_t), GFP_KERNEL);
    if (!result) {
        printk(KERN_ALERT "FAILED TO ALLOCATE MEMORY");
        return result;
    }
    INIT_LIST_HEAD(&(result->lh));
    result->data = data;
    printk(KERN_ALERT "created node: %p\n", result);
    return result;
}

void delete_stack_entry(stack_entry_t *entry)
{
    // if I understand correctly, taking care of *data
    // is not our responsibility, since we didn't create it
    printk(KERN_ALERT "deleting node: %p\n", entry);
    kfree(entry);
}

void stack_push(struct list_head *stack, stack_entry_t *entry)
{
    list_add(&(entry->lh), stack);
}

stack_entry_t* stack_pop(struct list_head *stack)
{
    stack_entry_t* result = list_entry(stack->next, stack_entry_t, lh);
    list_del(stack->next);
    return result;
}
