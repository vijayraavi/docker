package hcsshim

// 1. Copy UtilityVM\SystemTemplate.vhdx to scratch path

// 2. Grant VM Group Access to the scratch file
// +NT VIRTUAL MACHINE\Virtual Machines:(I)(F)

// 3. Create a UVM JSON document
//{
//   "Owner":"Demo",
//   "SchemaVersion":{
//      "Major":2,
//      "Minor":0
//   },
//   "ShouldTerminateOnLastHandleClosed":true,
//   "VirtualMachine":{
//      "Chipset":{
//         "UEFI":{
//            "BootThis":{
//               "device_path":"\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
//               "disk_number":0,
//               "optional_data":null,
//               "uefi_device":"VMBFS"
//            }
//         }
//      },
//      "ComputeTopology":{
//         "Memory":{
//            "Backing":"Virtual",
//            "Startup":2048
//         },
//         "Processor":{
//            "Count":1
//         }
//      },
//      "Devices":{
//         "GuestInterface":{
//            "BridgeFlags":0,
//            "ConnectToBridge":true
//         },
//         "SCSI":{
//            "primary":{
//               "Attachments":{
//                  "0":{
//                     "Path":"C:\\hcsdemoworkingdir\\uvm\\SystemTemplate.vhdx",
//                     "Type":"VirtualDisk"
//                  }
//               }
//            }
//         },
//         "VirtualSMBShares":[
//            {
//               "AllowedFiles":null,
//               "Flags":16785,
//               "Name":"os",
//               "Path":"C:\\CImages\\nanoserver\\UtilityVM\\Files"
//            }
//         ]
//      }
//   }
//}

// 4. Create the system  New-HcsSystem

// 5. Start it  Start-HcsSystem

// 6. Create container sandbox. sandbox.vhdx is a copy of blank.vhdx in the root of the image. Also creates layerchain.json

// 7. Grant VM group access   GrantVmAccess and RevokeVmAccess
// https://microsoft.visualstudio.com/DefaultCollection/OS/ft_vmc/_git/os?_a=contents&path=%2Fonecore%2Fvm%2Fcompute%2Fdll%2Fsrc%2FGraphDriver.cpp&version=GBofficial%2Frs_onecore_base2_hyp&line=1635&lineStyle=plain&lineEnd=1636&lineStartColumn=1&lineEndColumn=1
//
// +NT VIRTUAL MACHINE\Virtual Machines:(I)(F)
// +NT VIRTUAL MACHINE\Virtual Machines:(RX,W) ?? Was this added when the VM started?

// 8. Modify request [HCS.Schema.Requests.ModifySettingRequest] to add base image container layers to UVM as SMB shares
//{
//   "ResourceType":"VSmbShare",
//   "ResourceUri":"virtualmachine/devices/virtualsmbshares/baseimagelayer",
//   "Settings":{
//      "AllowedFiles":null,
//      "Flags":16401,   // "ReadOnly, PseudoOplocks, TakeBackupPrivilege"
//      "Name":"baseimagelayer",
//      "Path":"C:\\CImages\\nanoserver"
//   }
//}

// 9. Modify request [HCS.Schema.Requests.ModifySettingRequest] to attach containers scratch space
//{
//   "HostedSettings":{
//      "ContainerPath":"C:\\ContainerPath",
//      "CreateInUtilityVM":true,
//      "Lun":1
//   },
//   "ResourceType":"MappedVirtualDisk",
//   "ResourceUri":"virtualmachine/devices/scsi/primary/1",
//   "Settings":{
//      "Path":"C:\\hcsdemoworkingdir\\V2Xenon\\sandbox.vhdx",
//      "Type":"VirtualDisk"
//   }
//}

// 10. Modify request [HCS.Schema.Requests.ModifySettingRequest] to setup the storage filter in the UVM
//{
//   "HostedSettings":{
//      "ContainerRootPath":"C:\\ContainerPath",
//      "Layers":[
//         {
//            "Id":"7ec7af98-b778-53fb-8a4c-aea92540fa24",
//            "Path":"\\\\?\\VMSMB\\VSMB-{dcc079ae-60ba-4d07-847c-3493609c0870}\\baseimagelayer"
//         }
//      ]
//   },
//   "ResourceType":"CombinedLayers"
//}

// 11. Create hosted container JSON document
//{
//   "HostedSystem":{
//      "Container":{
//         "Storage":{
//            "Layers":[
//               {
//                  "Id":"7ec7af98-b778-53fb-8a4c-aea92540fa24",
//                  "Path":"\\\\?\\VMSMB\\VSMB-{dcc079ae-60ba-4d07-847c-3493609c0870}\\baseimagelayer"
//               }
//            ],
//            "Path":"C:\\ContainerPath"
//         }
//      },
//      "SchemaVersion":{
//         "Major":2,
//         "Minor":0
//      }
//   },
//   "HostingSystemId":"uvm",
//   "Owner":"Demo",
//   "SchemaVersion":{
//      "Major":2,
//      "Minor":0
//   },
//   "ShouldTerminateOnLastHandleClosed":true
//}

// 12. Create the system  New-HcsSystem

// 13. Start it  Start-HcsSystem
