
NM := nasm
CC := x86_64-w64-mingw32-gcc
LK := x86_64-w64-mingw32-ld

ASM := asm
INC := inc
SRC := src
BIN := bin
OBJ := obj

NAME := ws.exe

SRC_FILES := $(wildcard $(SRC)/*.c)
OBJ_FILES := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRC_FILES))

ASM_FILES := $(wildcard $(ASM)/*.asm)
ASM_OBJ_FILES := $(patsubst $(ASM)/%.asm, $(OBJ)/%.o, $(ASM_FILES))

LFLAGS := -s --no-seh
CFLAGS := -I $(INC) -s -m64 -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O0

all: $(BIN)/$(NAME)

$(BIN)/$(NAME): $(ASM_OBJ_FILES) $(OBJ_FILES) | $(BIN) $(OBJ)
	$(LK) $(LFLAGS) $^ -o $@

$(OBJ)/%.o: $(SRC)/%.c | $(OBJ)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.o: $(ASM)/%.asm | $(OBJ)
	$(NM) -f win64 $< -o $@

$(OBJ):
	mkdir -p $@

$(BIN):
	mkdir -p $@

clean:
	rm -rf $(BIN) $(OBJ)
