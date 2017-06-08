CC = clang-4.0
LL = llc-4.0
CFLAGS = -Wall -g -m32 -o1

# Safe Stack
SS_FLAG= -fsanitize=safe-stack -fno-stack-protector
# Stack Cookies
SC_FLAG= -fstack-protector

TARGET = rop2.c
BUILDDIR = build

SAFE = safe-stack
NOSAFE = stack-cookie


all: dir $(BUILDDIR)/$(SAFE) $(BUILDDIR)/$(NOSAFE)

dir:
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/$(SAFE): $(BUILDDIR)/$(SAFE).ll
	$(CC) $(CFLAGS) $(SS_FLAG) $? -o $@

$(BUILDDIR)/$(NOSAFE): $(BUILDDIR)/$(NOSAFE).ll
	$(CC) $(CFLAGS) $(SC_FLAG) $? -o $@

$(BUILDDIR)/$(SAFE).ll: $(TARGET)
	$(CC) -S -emit-llvm $(CFLAGS) $(SS_FLAG) -c $< -o $@

$(BUILDDIR)/$(NOSAFE).ll: $(TARGET)
	$(CC) -S -emit-llvm $(CFLAGS) $(SC_FLAG) -c $< -o $@

clean:
	rm -f $(BUILDDIR)/*~ $(BUILDDIR)/*.o $(BUILDDIR)/*.ll \
	$(BUILDDIR)/*.s $(BUILDDIR)/$(SAFE) $(BUILDDIR)/$(NOSAFE)

check:
	./checksec.sh --file $(BUILDDIR)/$(SAFE)
	./checksec.sh --file $(BUILDDIR)/$(NOSAFE)
