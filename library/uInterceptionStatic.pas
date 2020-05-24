unit uInterceptionStatic;

{$mode objfpc}{$H+}

interface

(*

  creating by mashing up

  https://github.com/oblitum/Interception/blob/master/library/interception.c#L1

  with

  https://github.com/r1me/Interception-Lazarus/blob/6a72b868ff6885c9561a1bca3bbff0d0656ff1db/library/uInterception.pas#L1

  (elminates the need for DLL, talks directly to driver using DeviceIoControl calls)

  note : filter predicates are no no longer cdecl

  also inlines some functions where appropriate

*)

const
  interception_driver_installed: boolean = False;

function interception_driver_installed_check: boolean;

const
  INTERCEPTION_MAX_KEYBOARD = 10;
  INTERCEPTION_MAX_MOUSE = 10;
  INTERCEPTION_MAX_DEVICE = ((INTERCEPTION_MAX_KEYBOARD) + (INTERCEPTION_MAX_MOUSE));

function INTERCEPTION_KEYBOARD(index: integer): integer;
function INTERCEPTION_MOUSE(index: integer): integer;

type
  InterceptionContext = Pointer;
  InterceptionDevice = integer;
  InterceptionPrecedence = integer;
  InterceptionFilter = word;

type
  InterceptionPredicate = function(device: InterceptionDevice): longbool;

const
  { InterceptionKeyState }
  INTERCEPTION_KEY_DOWN = $00;
  INTERCEPTION_KEY_UP = $01;
  INTERCEPTION_KEY_E0 = $02;
  INTERCEPTION_KEY_E1 = $04;
  INTERCEPTION_KEY_TERMSRV_SET_LED = $08;
  INTERCEPTION_KEY_TERMSRV_SHADOW = $10;
  INTERCEPTION_KEY_TERMSRV_VKPACKET = $20;

const
  { InterceptionFilterKeyState }
  INTERCEPTION_FILTER_KEY_NONE = $0000;
  INTERCEPTION_FILTER_KEY_ALL = $FFFF;
  INTERCEPTION_FILTER_KEY_DOWN = INTERCEPTION_KEY_UP;
  INTERCEPTION_FILTER_KEY_UP = INTERCEPTION_KEY_UP shl 1;
  INTERCEPTION_FILTER_KEY_E0 = INTERCEPTION_KEY_E0 shl 1;
  INTERCEPTION_FILTER_KEY_E1 = INTERCEPTION_KEY_E1 shl 1;
  INTERCEPTION_FILTER_KEY_TERMSRV_SET_LED = INTERCEPTION_KEY_TERMSRV_SET_LED shl 1;
  INTERCEPTION_FILTER_KEY_TERMSRV_SHADOW = INTERCEPTION_KEY_TERMSRV_SHADOW shl 1;
  INTERCEPTION_FILTER_KEY_TERMSRV_VKPACKET = INTERCEPTION_KEY_TERMSRV_VKPACKET shl 1;

const
  { InterceptionMouseState }
  INTERCEPTION_MOUSE_LEFT_BUTTON_DOWN = $001;
  INTERCEPTION_MOUSE_LEFT_BUTTON_UP = $002;
  INTERCEPTION_MOUSE_RIGHT_BUTTON_DOWN = $004;
  INTERCEPTION_MOUSE_RIGHT_BUTTON_UP = $008;
  INTERCEPTION_MOUSE_MIDDLE_BUTTON_DOWN = $010;
  INTERCEPTION_MOUSE_MIDDLE_BUTTON_UP = $020;

  INTERCEPTION_MOUSE_BUTTON_1_DOWN = INTERCEPTION_MOUSE_LEFT_BUTTON_DOWN;
  INTERCEPTION_MOUSE_BUTTON_1_UP = INTERCEPTION_MOUSE_LEFT_BUTTON_UP;
  INTERCEPTION_MOUSE_BUTTON_2_DOWN = INTERCEPTION_MOUSE_RIGHT_BUTTON_DOWN;
  INTERCEPTION_MOUSE_BUTTON_2_UP = INTERCEPTION_MOUSE_RIGHT_BUTTON_UP;
  INTERCEPTION_MOUSE_BUTTON_3_DOWN = INTERCEPTION_MOUSE_MIDDLE_BUTTON_DOWN;
  INTERCEPTION_MOUSE_BUTTON_3_UP = INTERCEPTION_MOUSE_MIDDLE_BUTTON_UP;

  INTERCEPTION_MOUSE_BUTTON_4_DOWN = $040;
  INTERCEPTION_MOUSE_BUTTON_4_UP = $080;
  INTERCEPTION_MOUSE_BUTTON_5_DOWN = $100;
  INTERCEPTION_MOUSE_BUTTON_5_UP = $200;

  INTERCEPTION_MOUSE_WHEEL = $400;
  INTERCEPTION_MOUSE_HWHEEL = $800;

const
  { InterceptionFilterMouseState }
  INTERCEPTION_FILTER_MOUSE_NONE = $0000;
  INTERCEPTION_FILTER_MOUSE_ALL = $FFFF;

  INTERCEPTION_FILTER_MOUSE_LEFT_BUTTON_DOWN = INTERCEPTION_MOUSE_LEFT_BUTTON_DOWN;
  INTERCEPTION_FILTER_MOUSE_LEFT_BUTTON_UP = INTERCEPTION_MOUSE_LEFT_BUTTON_UP;
  INTERCEPTION_FILTER_MOUSE_RIGHT_BUTTON_DOWN = INTERCEPTION_MOUSE_RIGHT_BUTTON_DOWN;
  INTERCEPTION_FILTER_MOUSE_RIGHT_BUTTON_UP = INTERCEPTION_MOUSE_RIGHT_BUTTON_UP;
  INTERCEPTION_FILTER_MOUSE_MIDDLE_BUTTON_DOWN = INTERCEPTION_MOUSE_MIDDLE_BUTTON_DOWN;
  INTERCEPTION_FILTER_MOUSE_MIDDLE_BUTTON_UP = INTERCEPTION_MOUSE_MIDDLE_BUTTON_UP;

  INTERCEPTION_FILTER_MOUSE_BUTTON_1_DOWN = INTERCEPTION_MOUSE_BUTTON_1_DOWN;
  INTERCEPTION_FILTER_MOUSE_BUTTON_1_UP = INTERCEPTION_MOUSE_BUTTON_1_UP;
  INTERCEPTION_FILTER_MOUSE_BUTTON_2_DOWN = INTERCEPTION_MOUSE_BUTTON_2_DOWN;
  INTERCEPTION_FILTER_MOUSE_BUTTON_2_UP = INTERCEPTION_MOUSE_BUTTON_2_UP;
  INTERCEPTION_FILTER_MOUSE_BUTTON_3_DOWN = INTERCEPTION_MOUSE_BUTTON_3_DOWN;
  INTERCEPTION_FILTER_MOUSE_BUTTON_3_UP = INTERCEPTION_MOUSE_BUTTON_3_UP;

  INTERCEPTION_FILTER_MOUSE_BUTTON_4_DOWN = INTERCEPTION_MOUSE_BUTTON_4_DOWN;
  INTERCEPTION_FILTER_MOUSE_BUTTON_4_UP = INTERCEPTION_MOUSE_BUTTON_4_UP;
  INTERCEPTION_FILTER_MOUSE_BUTTON_5_DOWN = INTERCEPTION_MOUSE_BUTTON_5_DOWN;
  INTERCEPTION_FILTER_MOUSE_BUTTON_5_UP = INTERCEPTION_MOUSE_BUTTON_5_UP;

  INTERCEPTION_FILTER_MOUSE_WHEEL = INTERCEPTION_MOUSE_WHEEL;
  INTERCEPTION_FILTER_MOUSE_HWHEEL = INTERCEPTION_MOUSE_HWHEEL;

  INTERCEPTION_FILTER_MOUSE_MOVE = $1000;

const
  { InterceptionMouseFlag }
  INTERCEPTION_MOUSE_MOVE_RELATIVE = $000;
  INTERCEPTION_MOUSE_MOVE_ABSOLUTE = $001;
  INTERCEPTION_MOUSE_VIRTUAL_DESKTOP = $002;
  INTERCEPTION_MOUSE_ATTRIBUTES_CHANGED = $004;
  INTERCEPTION_MOUSE_MOVE_NOCOALESCE = $008;
  INTERCEPTION_MOUSE_TERMSRV_SRC_SHADOW = $100;

type
  TInterceptionMouseStroke = record
    state: word;
    flags: word;
    rolling: smallint;
    x: integer;
    y: integer;
    information: cardinal;
  end;
  InterceptionMouseStroke = TInterceptionMouseStroke;
  PInterceptionMouseStroke = ^InterceptionMouseStroke;

type
  TInterceptionKeyStroke = record
    code: word;
    state: word;
    information: cardinal;
  end;
  InterceptionKeyStroke = TInterceptionKeyStroke;
  PInterceptionKeyStroke = ^InterceptionKeyStroke;

  InterceptionStroke = InterceptionMouseStroke;
  PInterceptionStroke = ^InterceptionStroke;

function interception_create_context: InterceptionContext;
procedure interception_destroy_context(context: InterceptionContext);
function interception_get_precedence(context: InterceptionContext;
  device: InterceptionDevice): InterceptionPrecedence;
procedure interception_set_precedence(context: InterceptionContext;
  device: InterceptionDevice; precedence: InterceptionPrecedence);
function interception_get_filter(context: InterceptionContext;
  device: InterceptionDevice): InterceptionFilter;
procedure interception_set_filter(context: InterceptionContext;
  interception_predicate: InterceptionPredicate; filter: InterceptionFilter);
function interception_wait(context: InterceptionContext): InterceptionDevice;
function interception_wait_with_timeout(context: InterceptionContext;
  milliseconds: NativeUInt): InterceptionDevice;
function interception_send(context: InterceptionContext;
  device: InterceptionDevice; const stroke: PInterceptionStroke;
  nstroke: cardinal): integer;
function interception_receive(context: InterceptionContext;
  device: InterceptionDevice; stroke: PInterceptionStroke; nstroke: cardinal): integer;
function interception_get_hardware_id(context: InterceptionContext;
  device: InterceptionDevice; hardware_id_buffer: Pointer;
  buffer_size: SizeInt): cardinal;
function interception_is_invalid(device: InterceptionDevice): longbool;
function interception_is_keyboard(device: InterceptionDevice): longbool;
function interception_is_mouse(device: InterceptionDevice): longbool;




implementation

uses Windows;

(*

from https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/specifying-device-types

#define FILE_DEVICE_UNKNOWN             0x00000022

*)

const
  FILE_DEVICE_UNKNOWN = $22;

(*

http://svn.netlabs.org/repos/odin32/tags/0.9.0/include/win/winioctl.h

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    (DWORD)((DeviceType)  shl  16) | ((Access)  shl  14) | ((Function)  shl  2) | (Method) \
)

#define FILE_ANY_ACCESS                 0
#define METHOD_BUFFERED                 0

*)

//#define IOCTL_SET_PRECEDENCE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
const
  IOCTL_SET_PRECEDENCE = (FILE_DEVICE_UNKNOWN shl 16) or ($801 shl 2);

//#define IOCTL_GET_PRECEDENCE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
const
  IOCTL_GET_PRECEDENCE = (FILE_DEVICE_UNKNOWN shl 16) or ($802 shl 2);


//#define IOCTL_SET_FILTER        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
const
  IOCTL_SET_FILTER = (FILE_DEVICE_UNKNOWN shl 16) or ($804 shl 2);

//#define IOCTL_GET_FILTER        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
const
  IOCTL_GET_FILTER = (FILE_DEVICE_UNKNOWN shl 16) or ($808 shl 2);

//#define IOCTL_SET_EVENT         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
const
  IOCTL_SET_EVENT = (FILE_DEVICE_UNKNOWN shl 16) or ($810 shl 2);

//#define IOCTL_WRITE             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
const
  IOCTL_WRITE = (FILE_DEVICE_UNKNOWN shl 16) or ($820 shl 2);

//#define IOCTL_READ              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)
const
  IOCTL_READ = (FILE_DEVICE_UNKNOWN shl 16) or ($840 shl 2);

//#define IOCTL_GET_HARDWARE_ID   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x880, METHOD_BUFFERED, FILE_ANY_ACCESS)
const
  IOCTL_GET_HARDWARE_ID = (FILE_DEVICE_UNKNOWN shl 16) or ($880 shl 2);



(*

typedef struct _KEYBOARD_INPUT_DATA
{
    USHORT UnitId;
    USHORT MakeCode;
    USHORT Flags;
    USHORT Reserved;
    ULONG  ExtraInformation;
} KEYBOARD_INPUT_DATA, *PKEYBOARD_INPUT_DATA;
*)

type
  PKEYBOARD_INPUT_DATA = ^KEYBOARD_INPUT_DATA;

  KEYBOARD_INPUT_DATA = record


    UnitId: word;
    MakeCode: word;
    Flags: word;
    Reserved: word;
    ExtraInformation: cardinal;


  end;

(*
typedef struct _MOUSE_INPUT_DATA
{
    USHORT UnitId;
    USHORT Flags;
    USHORT ButtonFlags;
    USHORT ButtonData;
    ULONG  RawButtons;
    LONG   LastX;
    LONG   LastY;
    ULONG  ExtraInformation;
} MOUSE_INPUT_DATA, *PMOUSE_INPUT_DATA;
*)
type
  PMOUSE_INPUT_DATA = ^MOUSE_INPUT_DATA;

  MOUSE_INPUT_DATA = record
    UnitId: word;
    Flags: word;
    ButtonFlags: word;
    ButtonData: word;
    RawButtons: cardinal;
    LastX: integer;
    LastY: integer;
    ExtraInformation: cardinal;
  end;
(*
typedef struct
{
    void *handle;
    void *unempty;
} *InterceptionDeviceArray;


*)
type
  InterceptionDeviceArray = ^_InterceptionDeviceArray;

  _InterceptionDeviceArray = record
    handle: HANDLE;
    unempty: HANDLE;
  end;



const
  interception_context_size = INTERCEPTION_MAX_DEVICE * sizeof(_InterceptionDeviceArray);

function interception_create_context: InterceptionContext;
  // see https://github.com/oblitum/Interception/blob/513556e660893ca294b2e287143abb40a9170bb3/library/interception.c#L43
var
  device_array: InterceptionDeviceArray;
  //                                         012345678901234567  8
var
  device_name: array [0..18] of char = '\\.\interception00'#0;
var
  device_name_num: PChar;
var
  bytes_returned: cardinal;
var
  i: InterceptionDevice;

var
  zero_padded_handle: array [0..1] of HANDLE;

const
  zero = Ord('0');
begin
  Result := nil;

  device_array := InterceptionDeviceArray(getMem(interception_context_size));
  if not assigned(device_array) then
    exit;

  Result := InterceptionContext(device_array);

  FillChar(device_array^, interception_context_size, 0);

  device_name_num := @device_name[16];

  for i := 0 to pred(INTERCEPTION_MAX_DEVICE) do
  begin
    device_name_num[0] := chr(zero + (i div 10));
    device_name_num[1] := chr(zero + (i mod 10));

    device_array[i].handle :=
      CreateFileA(device_name, GENERIC_READ, 0, nil, OPEN_EXISTING, 0, 0);

    if (device_array[i].handle = INVALID_HANDLE_VALUE) then
    begin
      interception_destroy_context(Result);
      Result := nil;
      exit;
    end;

    device_array[i].unempty := CreateEventA(nil, True, False, nil);


    if device_array[i].unempty = 0 then
    begin
      interception_destroy_context(Result);
      Result := nil;
      exit;
    end;

    zero_padded_handle[0] := device_array[i].unempty;
    zero_padded_handle[1] := 0;

    if (not DeviceIoControl(device_array[i].handle, IOCTL_SET_EVENT,
      @zero_padded_handle[0], sizeof(zero_padded_handle), nil, 0, @bytes_returned, nil)) then
    begin
      interception_destroy_context(Result);
      Result := nil;
      exit;
    end;

  end;

end;

procedure interception_destroy_context(context: InterceptionContext);
var
  device_array: InterceptionDeviceArray;
var
  i: integer;
begin
  if not assigned(context) then
    exit;

  device_array := InterceptionDeviceArray(context);


  for  i := 0 to pred(INTERCEPTION_MAX_DEVICE) do
  begin

    if (device_array[i].handle <> INVALID_HANDLE_VALUE) then
      CloseHandle(device_array[i].handle);

    if device_array[i].unempty <> 0 then
      CloseHandle(device_array[i].unempty);
  end;
  FreeMem(context, interception_context_size);
end;

function interception_get_precedence(context: InterceptionContext;
  device: InterceptionDevice): InterceptionPrecedence;
var
  device_array: InterceptionDeviceArray;
var
  bytes_returned: cardinal;
begin
  Result := 0;
  device_array := InterceptionDeviceArray(context);
  if (assigned(context) and (device_array[device - 1].handle <> 0)) then
  begin

    DeviceIoControl(device_array[device - 1].handle, IOCTL_GET_PRECEDENCE,
      nil, 0, @Result, sizeof(InterceptionPrecedence), @bytes_returned, nil);
  end;

end;

procedure interception_set_precedence(context: InterceptionContext;
  device: InterceptionDevice; precedence: InterceptionPrecedence);
var
  device_array: InterceptionDeviceArray;
var
  bytes_returned: cardinal;
begin
  device_array := InterceptionDeviceArray(context);
  if (assigned(context) and (device_array[device - 1].handle <> 0)) then
  begin
    DeviceIoControl(device_array[device - 1].handle, IOCTL_SET_PRECEDENCE,
      @precedence, sizeof(InterceptionPrecedence), nil, 0, @bytes_returned, nil);
  end;
end;

function interception_get_filter(context: InterceptionContext;
  device: InterceptionDevice): InterceptionFilter;
var
  device_array: InterceptionDeviceArray;
var
  bytes_returned: cardinal;
begin
  Result := 0;
  device_array := InterceptionDeviceArray(context);
  if (assigned(context) and (device_array[device - 1].handle <> 0)) then
  begin
    DeviceIoControl(device_array[device - 1].handle, IOCTL_GET_FILTER,
      nil, 0, @Result, sizeof(InterceptionFilter), @bytes_returned, nil);
  end;
end;


procedure interception_set_filter(context: InterceptionContext;
  interception_predicate: InterceptionPredicate; filter: InterceptionFilter);
var
  device_array: InterceptionDeviceArray;
var
  bytes_returned: cardinal;
var
  i: InterceptionDevice;
begin

  if assigned(context) then
  begin
    device_array := InterceptionDeviceArray(context);
    for i := 0 to pred(INTERCEPTION_MAX_DEVICE) do
    begin
      if ((device_array[i].handle <> 0) and interception_predicate(i + 1)) then
        DeviceIoControl(device_array[i].handle, IOCTL_SET_FILTER,
          @filter, sizeof(InterceptionFilter), nil, 0, @bytes_returned, nil);
    end;

  end;
end;

function interception_wait(context: InterceptionContext): InterceptionDevice;
begin
  Result := interception_wait_with_timeout(context, INFINITE);
end;

function interception_wait_with_timeout(context: InterceptionContext;
  milliseconds: NativeUInt): InterceptionDevice;
var
  device_array: InterceptionDeviceArray;
var
  wait_handles: array [0..pred(INTERCEPTION_MAX_DEVICE)] of HANDLE;
var
  i, j, k: cardinal;
begin
  Result := 0;
  if not assigned(context) then
    exit;

  device_array := InterceptionDeviceArray(context);

  j := 0;
  for i := 0 to pred(INTERCEPTION_MAX_DEVICE) do
  begin
    if (device_array[i].unempty <> 0) then
    begin
      wait_handles[j] := device_array[i].unempty;
      Inc(j);
    end;
  end;

  k := WaitForMultipleObjects(j, @wait_handles[0], False, milliseconds);

  if (k = WAIT_FAILED) or (k = WAIT_TIMEOUT) then
    exit;

  j := 0;
  for i := 0 to pred(INTERCEPTION_MAX_DEVICE) do
  begin
    if (device_array[i].unempty <> 0) then
    begin
      if (k = j) then
      begin
        break;
      end;
      Inc(j);
    end;
  end;

  Result := i + 1;

end;

function interception_send(context: InterceptionContext;
  device: InterceptionDevice; const stroke: PInterceptionStroke;
  nstroke: cardinal): integer;
var
  device_array: InterceptionDeviceArray;

  procedure sendKeystrokes;
  var
    rawstrokes: PKEYBOARD_INPUT_DATA;
  var
    rawstrokes_size: integer;
  var
    i: integer;
  var
    key_stroke: PInterceptionKeyStroke;
  begin
    rawstrokes_size := nstroke * sizeof(KEYBOARD_INPUT_DATA);

    rawstrokes := PKEYBOARD_INPUT_DATA(GetMem(rawstrokes_size));

    if not assigned(rawstrokes) then
      exit;

    key_stroke := PInterceptionKeyStroke(stroke);

    for i := 0 to pred(nstroke) do
    begin
      rawstrokes[i].UnitId := 0;
      rawstrokes[i].MakeCode := key_stroke[i].code;
      rawstrokes[i].Flags := key_stroke[i].state;
      rawstrokes[i].Reserved := 0;
      rawstrokes[i].ExtraInformation := key_stroke[i].information;
    end;

    DeviceIoControl(device_array[device - 1].handle, IOCTL_WRITE,
      @rawstrokes[0], rawstrokes_size, nil, 0, @Result, nil);

    freemem(rawstrokes, rawstrokes_size);

    Result := Result div sizeof(KEYBOARD_INPUT_DATA);
  end;

  procedure sendMouse;
  var
    rawstrokes: PMOUSE_INPUT_DATA;
  var
    rawstrokes_size: integer;
  var
    i: integer;
  var
    mouse_stroke: PInterceptionMouseStroke;

  begin

    rawstrokes_size := nstroke * sizeof(MOUSE_INPUT_DATA);

    rawstrokes := PMOUSE_INPUT_DATA(GetMem(rawstrokes_size));

    if not assigned(rawstrokes) then
      exit;

    mouse_stroke := PInterceptionMouseStroke(stroke);

    for i := 0 to pred(nstroke) do
    begin
      rawstrokes[i].UnitId := 0;
      rawstrokes[i].Flags := mouse_stroke[i].flags;
      rawstrokes[i].ButtonFlags := mouse_stroke[i].state;
      rawstrokes[i].ButtonData := mouse_stroke[i].rolling;
      rawstrokes[i].RawButtons := 0;
      rawstrokes[i].LastX := mouse_stroke[i].x;
      rawstrokes[i].LastY := mouse_stroke[i].y;
      rawstrokes[i].ExtraInformation := mouse_stroke[i].information;
    end;

    DeviceIoControl(device_array[device - 1].handle, IOCTL_WRITE, rawstrokes,
      rawstrokes_size, nil, 0, @Result, nil);

    freemem(rawstrokes, rawstrokes_size);

    Result := Result div sizeof(MOUSE_INPUT_DATA);

  end;

begin
  Result := 0;

  device_array := InterceptionDeviceArray(context);

  if not assigned(context) or (nstroke = 0) or
    interception_is_invalid(device) or
    (device_array[device - 1].handle = 0) then
    exit;

  if (interception_is_keyboard(device)) then
    sendKeystrokes
  else
    sendMouse;

end;


function interception_receive(context: InterceptionContext;
  device: InterceptionDevice; stroke: PInterceptionStroke; nstroke: cardinal): integer;
var
  device_array: InterceptionDeviceArray;

  procedure receiveKeystrokes;
  var
    rawstrokes: PKEYBOARD_INPUT_DATA;
  var
    rawstrokes_size: integer;
  var
    i: integer;
  var
    key_stroke: PInterceptionKeyStroke;
  begin
    rawstrokes_size := nstroke * sizeof(KEYBOARD_INPUT_DATA);

    rawstrokes := PKEYBOARD_INPUT_DATA(GetMem(rawstrokes_size));

    if not assigned(rawstrokes) then
      exit;

    key_stroke := PInterceptionKeyStroke(stroke);


    DeviceIoControl(device_array[device - 1].handle, IOCTL_READ,
      nil, 0, rawstrokes, rawstrokes_size, @Result, nil);

    Result := Result div sizeof(KEYBOARD_INPUT_DATA);

    for i := 0 to pred(Result) do
    begin
      key_stroke[i].code := rawstrokes[i].MakeCode;
      key_stroke[i].state := rawstrokes[i].Flags;
      key_stroke[i].information := rawstrokes[i].ExtraInformation;
    end;

    freemem(rawstrokes, rawstrokes_size);

  end;

  procedure receiveMouse;
  var
    rawstrokes: PMOUSE_INPUT_DATA;
  var
    rawstrokes_size: integer;
  var
    i: integer;
  var
    mouse_stroke: PInterceptionMouseStroke;

  begin

    rawstrokes_size := nstroke * sizeof(MOUSE_INPUT_DATA);

    rawstrokes := PMOUSE_INPUT_DATA(GetMem(rawstrokes_size));

    if not assigned(rawstrokes) then
      exit;

    mouse_stroke := PInterceptionMouseStroke(stroke);


    DeviceIoControl(device_array[device - 1].handle, IOCTL_READ,
      nil, 0, rawstrokes, rawstrokes_size, @Result, nil);

    Result := Result div sizeof(MOUSE_INPUT_DATA);

    for i := 0 to pred(Result) do
    begin
      mouse_stroke[i].flags := rawstrokes[i].Flags;
      mouse_stroke[i].state := rawstrokes[i].ButtonFlags;
      mouse_stroke[i].rolling := rawstrokes[i].ButtonData;
      mouse_stroke[i].x := rawstrokes[i].LastX;
      mouse_stroke[i].y := rawstrokes[i].LastY;
      mouse_stroke[i].information := rawstrokes[i].ExtraInformation;
    end;

    freemem(rawstrokes, rawstrokes_size);

  end;

begin
  Result := 0;

  device_array := InterceptionDeviceArray(context);

  if not assigned(context) or (nstroke = 0) or
    interception_is_invalid(device) or
    (device_array[device - 1].handle = 0) then
    exit;


  if (interception_is_keyboard(device)) then
    receiveKeystrokes
  else
    receiveMouse;

end;

function interception_get_hardware_id(context: InterceptionContext;
  device: InterceptionDevice; hardware_id_buffer: Pointer;
  buffer_size: SizeInt): cardinal;
var
  device_array: InterceptionDeviceArray;
begin
  Result := 0;

  device_array := InterceptionDeviceArray(context);

  if not assigned(context) or interception_is_invalid(device) or
    (device_array[device - 1].handle = 0) then
    exit;

  DeviceIoControl(device_array[device - 1].handle, IOCTL_GET_HARDWARE_ID,
    nil, 0, hardware_id_buffer, buffer_size, @Result, nil);

end;

function interception_is_invalid(device: InterceptionDevice): longbool;
begin
  Result := False;
  if interception_is_keyboard(device) then
    exit;
  if interception_is_mouse(device) then
    exit;
  Result := True;
end;

function interception_is_keyboard(device: InterceptionDevice): longbool;
begin
  Result := (device >= INTERCEPTION_KEYBOARD(0)) and
    (device <= INTERCEPTION_KEYBOARD(INTERCEPTION_MAX_KEYBOARD - 1));
end;

function interception_is_mouse(device: InterceptionDevice): longbool;
begin
  Result := (device >= INTERCEPTION_MOUSE(0)) and
    (device <= INTERCEPTION_MOUSE(INTERCEPTION_MAX_MOUSE - 1));
end;


function INTERCEPTION_KEYBOARD(index: integer): integer; inline;
const
  offset = 1;
begin
  Result := index + offset;
end;

function INTERCEPTION_MOUSE(index: integer): integer; inline;
const
  offset = INTERCEPTION_MAX_KEYBOARD + 1;
begin
  Result := index + offset;
end;


var
  test_context: InterceptionContext = nil;

function interception_driver_installed_check: boolean;
begin
  test_context := interception_create_context;
  interception_driver_installed := Assigned(test_context);
  interception_destroy_context(test_context);
  test_context := nil;
  Result := interception_driver_installed;
end;

initialization
{$IFNDEF INTERCEPTION_OBJECTS_SERVICE}
  interception_driver_installed_check;
{$ENDIF}
finalization

end.