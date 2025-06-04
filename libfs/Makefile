
CC      := gcc
CFLAGS  := -Wall -Wextra -Werror -I.

SRCS    := fs.c disk.c
OBJS    := $(SRCS:.c=.o)

LIB     := libfs.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(LIB)


%: 
	@$(MAKE) -C ../apps $@
