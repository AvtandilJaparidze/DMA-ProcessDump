.PHONY: all leechcore vmm memprocfs connector-qemu libs executable-dumper clean

all: leechcore vmm memprocfs connector-qemu executable-dumper libs

leechcore:
	$(MAKE) -C LeechCore/leechcore

vmm:
	$(MAKE) -C MemProcFS/vmm

memprocfs:
	$(MAKE) -C MemProcFS/memprocfs
	
connector-qemu:
	$(MAKE) -C LeechCore-plugins/leechcore_device_qemu
	
libs:
	@echo "Preparing output library folder..."
	mkdir -p ExecutableDumper/libs

	@echo "Copying required .so files to ExecutableDumper/libs..."
	cp MemProcFS/files/leechcore.so ExecutableDumper/libs/
	cp MemProcFS/files/vmm.so ExecutableDumper/libs/
	cp LeechCore-plugins/files/leechcore_device_qemu.so ExecutableDumper/libs/
	
executable-dumper:
	$(MAKE) -C ExecutableDumper

clean:
	$(MAKE) -C LeechCore/leechcore clean
	$(MAKE) -C MemProcFS/vmm clean
	$(MAKE) -C MemProcFS/memprocfs clean
	$(MAKE) -C LeechCore-plugins/leechcore_device_qemu clean
	rm -rf ExecutableDumper/libs
	$(MAKE) -C ExecutableDumper clean
