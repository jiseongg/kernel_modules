obj-m += lkm.o

all: check-kdir
	$(error)
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order

check-kdir:
ifndef KDIR
	$(error KDIR, kernel source directory is undefined)
endif
