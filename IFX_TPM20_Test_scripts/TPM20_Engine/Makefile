#CC_FLAGS   += -DDEBUG
CC_FLAGS   += -std=c99 -Dlinux -DVERSION=0
CC_FLAGS   += -I/usr/local/include/tcti -I/usr/local/include/sapi
CC_FLAGS   += -I/usr/local/include/tcti -I/usr/local/include/sapi
CC_FLAGS   += -I./src
CC_FLAGS   += -Wshadow -Wall -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes
CC_FLAGS   += -g
LD_FLAGS   += -lssl \
              -lcrypto \
              -lcurl \
              -lsapi \
              -ltcti-socket \
              -ltcti-device 
              #-L/usr/local/lib -Wl,-rpath /usr/local/lib \
              #/usr/local/lib/libtcti-socket.so /usr/local/lib/libtcti-device.so /usr/local/lib/libsapi.so \
              #	-Wl,--no-undefined

OBJ_DIR   = obj
LIB_DIR   = lib
SRC_DIR   = src

SRCS      = $(wildcard $(SRC_DIR)/*.c)
OBJS      = $(addprefix $(OBJ_DIR)/,$(notdir $(SRCS:.c=.o)))

all: engine

engine: $(OBJS)
	@mkdir -p $(LIB_DIR)
	$(CC) $(LD_FLAGS) $^ -shared -o $(LIB_DIR)/libtpm20e.so

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CC_FLAGS) -c -fpic $< -o $@

install: uninstall
	ln -s $(realpath $(LIB_DIR)/libtpm20e.so) /usr/lib/arm-linux-gnueabihf/openssl-1.0.0/engines/libtpm20e_v2.so

uninstall:
	rm -f /usr/lib/arm-linux-gnueabihf/openssl-1.0.0/engines/libtpm20e_v2.so

clean:
	rm -rf $(OBJ_DIR) $(LIB_DIR)



# KNOW-HOW
# The variable $@ is set to the name of the target.
# The variable $^ holds the names of all prerequisites.
# The variable $< holds the name of the first prerequisite.
