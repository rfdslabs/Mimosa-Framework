# This will point to the root of the FERRET project
SRCDIR = src
DSTDIR = bin
TMPDIR = tmp

LIBS = -ldl -lpthread -lSegFault
INCLUDES= 

CC = gcc
CFLAGS = -g $(INCLUDES) -Wall -rdynamic

.SUFFIXES: .c .cpp


$(TMPDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@


main_sources := $(wildcard $(SRCDIR)/*.c)

SRC = $(main_sources) 

OBJ = $(addprefix $(TMPDIR)/, $(notdir $(addsuffix .o, $(basename $(SRC))))) $(TMPDIR)/main.o

$(DSTDIR)/ferret: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) -lm $(LIBS) -lstdc++ -rdynamic

depend:
	makedepend $(CFLAGS) -Y $(SRC)

clean:
	rm -f $(OBJ)


$(TMPDIR)/main.o: $(SRCDIR)/main.cpp
	$(CC) $(CFLAGS) -c $< -o $@
