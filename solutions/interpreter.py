import jpamb
from jpamb import jvm
from dataclasses import dataclass

import sys
from loguru import logger

logger.remove()
logger.add(sys.stderr, format="[{level}] {message}")

methodid, input = jpamb.getcase()


@dataclass
class PC:
    method: jvm.AbsMethodID
    offset: int

    def __iadd__(self, delta):
        self.offset += delta
        return self

    def __add__(self, delta):
        return PC(self.method, self.offset + delta)

    def __str__(self):
        return f"{self.method}:{self.offset}"


@dataclass
class Bytecode:
    suite: jpamb.Suite
    methods: dict[jvm.AbsMethodID, list[jvm.Opcode]]

    def __getitem__(self, pc: PC) -> jvm.Opcode:
        try:
            opcodes = self.methods[pc.method]
        except KeyError:
            opcodes = list(self.suite.method_opcodes(pc.method))
            self.methods[pc.method] = opcodes

        return opcodes[pc.offset]


@dataclass
class Stack[T]:
    items: list[T]

    def __bool__(self) -> bool:
        return len(self.items) > 0

    @classmethod
    def empty(cls):
        return cls([])

    def peek(self) -> T:
        return self.items[-1]

    def pop(self) -> T:
        return self.items.pop(-1)

    def push(self, value):
        self.items.append(value)
        return self

    def __str__(self):
        if not self:
            return "ϵ"
        return "".join(f"{v}" for v in self.items)


suite = jpamb.Suite()
bc = Bytecode(suite, dict())


@dataclass
class Frame:
    locals: dict[int, jvm.Value]
    stack: Stack[jvm.Value]
    pc: PC

    def __str__(self):
        locals = ", ".join(f"{k}:{v}" for k, v in sorted(self.locals.items()))
        return f"<{{{locals}}}, {self.stack}, {self.pc}>"

    def from_method(method: jvm.AbsMethodID) -> "Frame":
        return Frame({}, Stack.empty(), PC(method, 0))


@dataclass
class State:
    heap: dict[int, jvm.Value]
    frames: Stack[Frame]

    def __str__(self):
        return f"{self.heap} {self.frames}"


def step(state: State) -> State | str:
    assert isinstance(state, State), f"expected frame but got {state}"
    frame = state.frames.peek()
    opr = bc[frame.pc]
    logger.debug(f"STEP {opr}\n{state}")
    match opr:
        case jvm.Push(value=v):
            frame.stack.push(v)
            frame.pc += 1
            return state
        case jvm.Load(type=jvm.Int(), index=i):
            frame.stack.push(frame.locals[i])
            frame.pc += 1
            return state
        case jvm.Binary(type=jvm.Int(), operant=operant):
            v2, v1 = frame.stack.pop(), frame.stack.pop()
            assert v1.type is jvm.Int(), f"expected int, but got {v1}"
            assert v2.type is jvm.Int(), f"expected int, but got {v2}"
            
            match operant:
                case jvm.BinaryOpr.Div:
                    if v2.value == 0:
                        return "divide by zero"
                    result = v1.value // v2.value
                case jvm.BinaryOpr.Add:
                    result = v1.value + v2.value
                case jvm.BinaryOpr.Sub:
                    result = v1.value - v2.value
                case jvm.BinaryOpr.Mul:
                    result = v1.value * v2.value
                case _:
                    raise NotImplementedError(f"Unsupported binary operator: {operant}")
            
            frame.stack.push(jvm.Value.int(result))
            frame.pc += 1
            return state
        case jvm.Get(static=True, field=field):
            # For static field access, particularly $assertionsDisabled
            if field.extension.name == "$assertionsDisabled":
                # Java assertions are typically disabled, so return false
                frame.stack.push(jvm.Value.boolean(False))
            else:
                # Default to zero/false for other static fields
                if isinstance(field.extension.type, jvm.Boolean):
                    frame.stack.push(jvm.Value.boolean(False))
                elif isinstance(field.extension.type, jvm.Int):
                    frame.stack.push(jvm.Value.int(0))
                else:
                    raise NotImplementedError(f"Unsupported static field type: {field.extension.type}")
            frame.pc += 1
            return state
        case jvm.Ifz(condition=condition, target=target):
            v = frame.stack.pop()
            conditions = {
                "eq": lambda val: val == 0,
                "ne": lambda val: val != 0,
                "lt": lambda val: val < 0,
                "le": lambda val: val <= 0,
                "gt": lambda val: val > 0,
                "ge": lambda val: val >= 0,
            }
            if condition not in conditions:
                raise NotImplementedError(f"Unsupported Ifz condition: {condition}")
            
            if conditions[condition](v.value):
                frame.pc = PC(frame.pc.method, target)
            else:
                frame.pc += 1
            return state
        case jvm.Return(type=jvm.Int()):
            v1 = frame.stack.pop()
            state.frames.pop()
            if state.frames:
                frame = state.frames.peek()
                frame.stack.push(v1)
                frame.pc += 1
                return state
            else:
                return "ok"
        case jvm.Return(type=None):  # Void return
            state.frames.pop()
            if state.frames:
                frame = state.frames.peek()
                frame.pc += 1
                return state
            else:
                return "ok"
        case jvm.New(classname=classname):
            # Handle creation of new objects, especially exceptions
            if str(classname) == "java/lang/AssertionError":
                return "assertion error"
            else:
                # For other classes, create a simple object reference and push to stack
                # Using a simple object ID based on the class name
                object_ref = jvm.Value(jvm.Reference(), f"ref_{classname}")
                frame.stack.push(object_ref)
                frame.pc += 1
                return state
        case jvm.If(condition=condition, target=target):
            # Compare two values on the stack
            v2, v1 = frame.stack.pop(), frame.stack.pop()
            conditions = {
                "eq": lambda v1, v2: v1 == v2,
                "ne": lambda v1, v2: v1 != v2,
                "lt": lambda v1, v2: v1 < v2,
                "le": lambda v1, v2: v1 <= v2,
                "gt": lambda v1, v2: v1 > v2,
                "ge": lambda v1, v2: v1 >= v2,
            }
            if condition not in conditions:
                raise NotImplementedError(f"Unsupported If condition: {condition}")
            
            if conditions[condition](v1.value, v2.value):
                frame.pc = PC(frame.pc.method, target)
            else:
                frame.pc += 1
            return state
        case a:
            raise NotImplementedError(f"Don't know how to handle: {a!r}")


frame = Frame.from_method(methodid)
for i, v in enumerate(input.values):
    frame.locals[i] = v

state = State({}, Stack.empty().push(frame))

for x in range(1000):
    state = step(state)
    if isinstance(state, str):
        print(state)
        break
else:
    print("*")
