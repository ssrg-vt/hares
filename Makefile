## Makefile template from:
## https://stackoverflow.com/questions/5178125/how-to-place-object-files-in-separate-subdirectory
# Compiler and Linker
CC          := gcc

# The Target Binary Program
TARGET      := popSGX_Monitor

# The Directories, Source, Includes, Objects, Binary and Resources
SRCDIR      := src
INCDIR      := inc
BUILDDIR    := obj
TARGETDIR   := bin
RESDIR      := res
SRCEXT      := c
DEPEXT      := d
OBJEXT      := o

# Flags, Libraries and Includes
CFLAGS      := -Wall -O3 -g -DNDEBUG 
LIB         := -lpthread -lcjson
INC         := -I$(INCDIR) -I/usr/local/include 
INCDEP      := -I$(INCDIR)

# Compel Macros
COMPEL          := ../../crui-untouched/criu-3.16.1/compel/compel-host
COMPEL_INC      := $(shell $(COMPEL) includes)
COMPEL_SLIBS    := $(shell $(COMPEL) --static libs)

# Parasite Macros
PARASITE_SRCDIR     := ./parasite_src

SOURCES     := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS     := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.$(OBJEXT)))

# Defauilt Make
#all: resources $(TARGET)
all: prepare parasite $(TARGET)

# Generating parasite header for compel injection
parasite: $(INCDIR)/parasite.h

$(INCDIR)/parasite.h: $(PARASITE_SRCDIR)/parasite.po
	$(COMPEL) hgen -o $@ -f $<

$(PARASITE_SRCDIR)/parasite.po: $(PARASITE_SRCDIR)/parasite.o 
	ld $(shell $(COMPEL) ldflags) -o $@ $< $(shell $(COMPEL) plugins fds)

$(PARASITE_SRCDIR)/parasite.o: $(PARASITE_SRCDIR)/parasite.c
	$(CC) $(CFLAGS) -c $(shell $(COMPEL) cflags) -o $@ $^

parasite_clean: 
	@$(RM) -f $(INCDIR)/parasite.h
	@$(RM) -f $(PARASITE_SRCDIR)/parasite.po
	@$(RM) -f $(PARASITE_SRCDIR)/parasite.o

# Prepare directory for building process.
# i.e., bin/
prepare:
	@mkdir -p $(TARGETDIR)

# Remake
remake: cleaner all

# Copy Resources from Resources Directory to Target Directory
resources: directories
	@cp $(RESDIR)/* $(TARGETDIR)/

# Make the Directories
directories:
	@mkdir -p $(TARGETDIR)
	@mkdir -p $(BUILDDIR)

# Clean only Objecst
clean: parasite_clean
	@$(RM) -rf $(TARGETDIR)
	@$(RM) -rf $(BUILDDIR)

# Full Clean, Objects and Binaries
distclean: clean
	@$(RM) -rf $(TARGETDIR)

# Pull in dependency info for *existing* .o files
-include $(OBJECTS:.$(OBJEXT)=.$(DEPEXT))

# Link
$(TARGET): $(OBJECTS)
	$(CC) -o $(TARGETDIR)/$(TARGET) $^ $(LIB)  $(shell $(COMPEL) --static libs)

# Compile
$(BUILDDIR)/%.$(OBJEXT): $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) $(shell $(COMPEL) includes) -c -o $@ $< 
	@$(CC) $(CFLAGS) $(INCDEP) -MM $(SRCDIR)/$*.$(SRCEXT) > $(BUILDDIR)/$*.$(DEPEXT)
	@cp -f $(BUILDDIR)/$*.$(DEPEXT) $(BUILDDIR)/$*.$(DEPEXT).tmp
	@sed -e 's|.*:|$(BUILDDIR)/$*.$(OBJEXT):|' < $(BUILDDIR)/$*.$(DEPEXT).tmp > $(BUILDDIR)/$*.$(DEPEXT)
	@sed -e 's/.*://' -e 's/\\$$//' < $(BUILDDIR)/$*.$(DEPEXT).tmp | fmt -1 | sed -e 's/^ *//' -e 's/$$/:/' >> $(BUILDDIR)/$*.$(DEPEXT)
	@rm -f $(BUILDDIR)/$*.$(DEPEXT).tmp

# Non-File Targets
.PHONY: all remake clean cleaner resources
