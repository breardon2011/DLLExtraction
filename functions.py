import os
import re
import json
import hashlib
from typing import List, Dict, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
import ast
import logging

# Setup logging for debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DecompilerType(Enum):
    IDA_PRO = "ida"
    GHIDRA = "ghidra"
    RADARE2 = "radare2"
    BINARY_NINJA = "binja"
    RETDEC = "retdec"
    GENERIC = "generic"

class CallingConvention(Enum):
    CDECL = "__cdecl"
    STDCALL = "__stdcall"
    FASTCALL = "__fastcall"
    THISCALL = "__thiscall"
    VECTORCALL = "__vectorcall"
    CLRCALL = "__clrcall"

@dataclass
class Variable:
    name: str
    type_info: str
    scope: str  # global, local, parameter
    is_pointer: bool = False
    array_size: Optional[int] = None
    initialization: Optional[str] = None
    is_const: bool = False
    is_volatile: bool = False
    alignment: Optional[int] = None

@dataclass
class Structure:
    name: str
    fields: Dict[str, Variable]
    size: Optional[int] = None
    alignment: Optional[int] = None
    is_packed: bool = False
    is_union: bool = False
    inheritance: Optional[str] = None  # For C++ classes
    vtable_offset: Optional[int] = None

@dataclass
class Function:
    name: str
    original_name: str  # Might be mangled
    return_type: str
    parameters: List[Variable]
    body: str
    is_exported: bool = False
    is_imported: bool = False
    calling_convention: CallingConvention = CallingConvention.CDECL
    dependencies: Set[str] = field(default_factory=set)
    used_globals: Set[str] = field(default_factory=set)
    local_variables: Dict[str, Variable] = field(default_factory=dict)
    inline_assembly: List[str] = field(default_factory=list)
    exception_handlers: List[str] = field(default_factory=list)
    address: Optional[int] = None
    size: Optional[int] = None
    ordinal: Optional[int] = None
    is_thunk: bool = False
    confidence: float = 1.0  # Decompiler confidence score
    optimization_level: str = "unknown"
    complexity_score: int = 0
    cyclomatic_complexity: int = 1

@dataclass
class StringLiteral:
    value: str
    encoding: str = "ascii"
    address: Optional[int] = None
    references: Set[str] = field(default_factory=set)

@dataclass
class ImportFunction:
    name: str
    module: str
    ordinal: Optional[int] = None
    is_delayed: bool = False

class RobustDLLHandler:
    def __init__(self, input_dir: str = "input", output_dir: str = "output"):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        
        # Core data structures
        self.functions: Dict[str, Function] = {}
        self.structures: Dict[str, Structure] = {}
        self.global_variables: Dict[str, Variable] = {}
        self.string_literals: Dict[str, StringLiteral] = {}
        self.imports: Dict[str, ImportFunction] = {}
        self.exports: Set[str] = set()
        self.typedefs: Dict[str, str] = {}
        
        # Analysis data
        self.decompiler_type: DecompilerType = DecompilerType.GENERIC
        self.architecture: str = "x64"  # x86, x64, arm, etc.
        self.compiler_info: Dict[str, str] = {}
        self.obfuscation_detected: bool = False
        self.anti_debug_detected: bool = False
        
        # Processing statistics
        self.stats = {
            'functions_processed': 0,
            'functions_failed': 0,
            'structures_found': 0,
            'imports_resolved': 0,
            'strings_extracted': 0,
            'complexity_warnings': 0
        }
        
        self._setup_directories()
        self._setup_patterns()

    def _setup_directories(self):
        """Create all necessary directories"""
        directories = [
            self.output_dir,
            self.output_dir / 'include',
            self.output_dir / 'src',
            self.output_dir / 'resources',
            self.output_dir / 'analysis',
            self.output_dir / 'debug'
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def _setup_patterns(self):
        """Setup comprehensive regex patterns for different decompilers"""
        self.patterns = {
            # Function patterns for different decompilers
            'ida_function': r'(?:(?:DLLEXPORT|__declspec\(dllexport\))\s+)?(\w+(?:\s+\*)*)\s+(?:__(?:cdecl|stdcall|fastcall|thiscall)__)?\s*(\w+)\s*\(([^)]*)\)\s*(\{(?:[^{}]*\{[^{}]*\})*[^{}]*\})',
            'ghidra_function': r'(\w+(?:\s+\*)*)\s+(\w+)\s*\(([^)]*)\)\s*(\{(?:[^{}]*\{[^{}]*\})*[^{}]*\})',
            'generic_function': r'(\w+(?:\s+\*)*)\s+(\w+)\s*\(([^)]*)\)\s*(\{(?:[^{}]*\{[^{}]*\})*[^{}]*\})',
            
            # Structure patterns
            'struct_def': r'(?:typedef\s+)?struct\s+(\w+)?\s*\{([^}]+)\}\s*(\w+)?(?:\s*,\s*\*(\w+))?\s*;',
            'union_def': r'(?:typedef\s+)?union\s+(\w+)?\s*\{([^}]+)\}\s*(\w+)?(?:\s*,\s*\*(\w+))?\s*;',
            
            # Variable patterns
            'global_var': r'^(?:extern\s+)?(?:static\s+)?(?:const\s+)?(?:volatile\s+)?(\w+(?:\s+\w+)*)\s+(\*?\s*\w+)(?:\[([^\]]*)\])?\s*(?:=\s*([^;]+))?\s*;',
            'local_var': r'^\s*(?:static\s+)?(?:const\s+)?(?:volatile\s+)?(\w+(?:\s+\w+)*)\s+(\*?\s*\w+)(?:\[([^\]]*)\])?\s*(?:=\s*([^;]+))?\s*;',
            
            # String literals
            'string_literal': r'"([^"\\]|\\.)*"',
            'wide_string': r'L"([^"\\]|\\.)*"',
            
            # Calling conventions
            'calling_conv': r'__(?:cdecl|stdcall|fastcall|thiscall|vectorcall|clrcall)__',
            
            # Assembly inline
            'inline_asm': r'__asm\s*\{([^}]+)\}',
            'asm_block': r'asm\s*\(([^)]+)\)',
            
            # Exports/Imports
            'dllexport': r'__declspec\s*\(\s*dllexport\s*\)',
            'dllimport': r'__declspec\s*\(\s*dllimport\s*\)',
            
            # Obfuscation indicators
            'obfuscated_name': r'\b(?:sub_[0-9A-F]+|loc_[0-9A-F]+|unk_[0-9A-F]+|byte_[0-9A-F]+|word_[0-9A-F]+|dword_[0-9A-F]+|qword_[0-9A-F]+)\b',
            'anti_debug': r'\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString|DebugBreak)\b'
        }

    def detect_decompiler(self, content: str) -> DecompilerType:
        """Detect which decompiler was used based on code patterns"""
        indicators = {
            DecompilerType.IDA_PRO: [r'sub_[0-9A-F]{6,8}', r'loc_[0-9A-F]{6,8}', r'// IDA'],
            DecompilerType.GHIDRA: [r'undefined\d+', r'FUN_[0-9a-f]{8}', r'// WARNING:'],
            DecompilerType.RADARE2: [r'fcn\.[0-9a-f]{8}', r'// r2'],
            DecompilerType.BINARY_NINJA: [r'sub_[0-9a-f]+', r'// Binary Ninja'],
            DecompilerType.RETDEC: [r'function_[0-9a-f]+', r'// RetDec']
        }
        
        for decompiler, patterns in indicators.items():
            if all(re.search(pattern, content, re.MULTILINE | re.IGNORECASE) for pattern in patterns[:1]):
                logger.info(f"Detected decompiler: {decompiler.value}")
                return decompiler
        
        return DecompilerType.GENERIC

    def analyze_architecture(self, content: str) -> str:
        """Detect target architecture"""
        if any(keyword in content for keyword in ['__int64', 'QWORD', '_m128']):
            return "x64"
        elif any(keyword in content for keyword in ['DWORD', '__int32']):
            return "x86"
        elif any(keyword in content for keyword in ['_ARM', '__arm']):
            return "arm"
        return "unknown"

    def extract_compiler_info(self, content: str) -> Dict[str, str]:
        """Extract compiler-specific information"""
        info = {}
        
        # MSVC indicators
        if re.search(r'__declspec|_MSC_VER|__stdcall', content):
            info['compiler'] = 'MSVC'
            
        # GCC indicators
        elif re.search(r'__attribute__|__GNUC__', content):
            info['compiler'] = 'GCC'
            
        # Clang indicators
        elif re.search(r'__clang__|__has_builtin', content):
            info['compiler'] = 'Clang'
            
        # Detect optimization level
        if 'O0' in content or any(name in content for name in ['debug_info', 'line_number']):
            info['optimization'] = 'O0'
        elif any(keyword in content for keyword in ['inline', 'unroll']):
            info['optimization'] = 'O2+'
        
        return info

    def extract_string_literals(self, content: str) -> None:
        """Extract and catalog string literals"""
        # Regular strings
        for match in re.finditer(self.patterns['string_literal'], content):
            string_val = match.group(0)[1:-1]  # Remove quotes
            string_hash = hashlib.md5(string_val.encode()).hexdigest()[:8]
            
            self.string_literals[f"str_{string_hash}"] = StringLiteral(
                value=string_val,
                encoding="ascii"
            )
            
        # Wide strings
        for match in re.finditer(self.patterns['wide_string'], content):
            string_val = match.group(0)[2:-1]  # Remove L" and "
            string_hash = hashlib.md5(string_val.encode()).hexdigest()[:8]
            
            self.string_literals[f"wstr_{string_hash}"] = StringLiteral(
                value=string_val,
                encoding="utf-16"
            )

    def extract_structures_comprehensive(self, content: str) -> None:
        """Comprehensive structure extraction"""
        # Handle struct definitions
        for match in re.finditer(self.patterns['struct_def'], content, re.MULTILINE | re.DOTALL):
            struct_name = match.group(3) or match.group(1) or f"struct_{len(self.structures)}"
            fields_text = match.group(2)
            
            fields = {}
            for field_line in fields_text.split(';'):
                field_line = field_line.strip()
                if not field_line:
                    continue
                    
                # Parse field: type name;
                field_match = re.match(r'(\w+(?:\s+\w+)*)\s+(\*?\s*\w+)(?:\[([^\]]*)\])?', field_line)
                if field_match:
                    field_type = field_match.group(1)
                    field_name = field_match.group(2).strip()
                    array_size = field_match.group(3)
                    
                    fields[field_name] = Variable(
                        name=field_name,
                        type_info=field_type,
                        scope="struct",
                        is_pointer="*" in field_name,
                        array_size=int(array_size) if array_size and array_size.isdigit() else None
                    )
            
            self.structures[struct_name] = Structure(
                name=struct_name,
                fields=fields
            )

    def extract_functions_comprehensive(self, content: str) -> None:
        """Ultra-comprehensive function extraction"""
        # Choose pattern based on detected decompiler
        if self.decompiler_type == DecompilerType.IDA_PRO:
            pattern = self.patterns['ida_function']
        elif self.decompiler_type == DecompilerType.GHIDRA:
            pattern = self.patterns['ghidra_function']
        else:
            pattern = self.patterns['generic_function']
        
        for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
            try:
                return_type = match.group(1).strip()
                func_name = match.group(2).strip()
                params_str = match.group(3).strip() if match.group(3) else ""
                body = match.group(4) if match.group(4) else ""
                
                # Skip if this looks like a variable declaration
                if not body or len(body) < 3:
                    continue
                
                # Parse parameters
                parameters = []
                if params_str and params_str != "void":
                    for param in params_str.split(','):
                        param = param.strip()
                        if param:
                            param_match = re.match(r'(\w+(?:\s+\w+)*)\s+(\*?\s*\w+)', param)
                            if param_match:
                                parameters.append(Variable(
                                    name=param_match.group(2).strip(),
                                    type_info=param_match.group(1).strip(),
                                    scope="parameter",
                                    is_pointer="*" in param_match.group(2)
                                ))
                
                # Detect calling convention
                calling_conv = CallingConvention.CDECL
                conv_match = re.search(self.patterns['calling_conv'], return_type + params_str)
                if conv_match:
                    conv_str = conv_match.group(0)
                    for conv in CallingConvention:
                        if conv.value in conv_str:
                            calling_conv = conv
                            break
                
                # Check if exported
                is_exported = bool(re.search(self.patterns['dllexport'], content[:match.start()]))
                
                # Extract dependencies (function calls)
                dependencies = set()
                for func_call in re.finditer(r'\b(\w+)\s*\(', body):
                    call_name = func_call.group(1)
                    if call_name != func_name and not call_name in ['if', 'while', 'for', 'switch']:
                        dependencies.add(call_name)
                
                # Extract local variables
                local_vars = {}
                for var_match in re.finditer(self.patterns['local_var'], body, re.MULTILINE):
                    var_type = var_match.group(1)
                    var_name = var_match.group(2).strip()
                    var_init = var_match.group(4)
                    
                    local_vars[var_name] = Variable(
                        name=var_name,
                        type_info=var_type,
                        scope="local",
                        is_pointer="*" in var_name,
                        initialization=var_init
                    )
                
                # Extract inline assembly
                inline_asm = []
                for asm_match in re.finditer(self.patterns['inline_asm'], body):
                    inline_asm.append(asm_match.group(1))
                
                # Calculate complexity
                complexity = self.calculate_complexity(body)
                
                # Create function object
                function = Function(
                    name=func_name,
                    original_name=func_name,  # Could be enhanced to detect mangling
                    return_type=return_type,
                    parameters=parameters,
                    body=body,
                    is_exported=is_exported,
                    calling_convention=calling_conv,
                    dependencies=dependencies,
                    local_variables=local_vars,
                    inline_assembly=inline_asm,
                    complexity_score=complexity['total'],
                    cyclomatic_complexity=complexity['cyclomatic']
                )
                
                self.functions[func_name] = function
                if is_exported:
                    self.exports.add(func_name)
                    
                self.stats['functions_processed'] += 1
                
            except Exception as e:
                logger.warning(f"Failed to process function: {e}")
                self.stats['functions_failed'] += 1

    def calculate_complexity(self, code: str) -> Dict[str, int]:
        """Calculate various complexity metrics"""
        # Lines of code
        loc = len([line for line in code.split('\n') if line.strip()])
        
        # Cyclomatic complexity (simplified)
        decision_points = len(re.findall(r'\b(?:if|while|for|switch|case|\?)\b', code))
        cyclomatic = decision_points + 1
        
        # Nesting depth
        max_depth = 0
        current_depth = 0
        for char in code:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth -= 1
        
        return {
            'total': loc + decision_points + max_depth,
            'cyclomatic': cyclomatic,
            'loc': loc,
            'nesting': max_depth
        }

    def detect_obfuscation(self, content: str) -> bool:
        """Detect various obfuscation techniques"""
        indicators = [
            # High ratio of hex addresses
            len(re.findall(r'\b0x[0-9A-Fa-f]{6,}\b', content)) > 50,
            # Lots of generic names
            len(re.findall(self.patterns['obfuscated_name'], content)) > 20,
            # Excessive complexity
            len(re.findall(r'\bgoto\b', content)) > 10,
            # String obfuscation
            len(re.findall(r'["\'][^"\']{50,}["\']', content)) > 5
        ]
        
        return sum(indicators) >= 2

    def detect_anti_debug(self, content: str) -> bool:
        """Detect anti-debugging techniques"""
        return bool(re.search(self.patterns['anti_debug'], content))

    def generate_makefile(self) -> str:
        """Generate comprehensive Makefile"""
        makefile_content = f"""# Auto-generated Makefile for reconstructed DLL
# Architecture: {self.architecture}
# Decompiler: {self.decompiler_type.value}

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -shared
TARGET = reconstructed.dll
OBJDIR = obj
SRCDIR = src
INCDIR = include

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Default target
all: $(TARGET)

# Create object directory
$(OBJDIR):
\tmkdir -p $(OBJDIR)

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
\t$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

# Link the DLL
$(TARGET): $(OBJECTS)
\t$(CC) $(LDFLAGS) -o $@ $^

# Clean build artifacts
clean:
\trm -rf $(OBJDIR) $(TARGET)

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Analysis target
analyze:
\t@echo "Functions: {len(self.functions)}"
\t@echo "Structures: {len(self.structures)}"
\t@echo "Exports: {len(self.exports)}"
\t@echo "Complexity warnings: {self.stats['complexity_warnings']}"

.PHONY: all clean debug analyze
"""
        return makefile_content

    def generate_comprehensive_header(self) -> str:
        """Generate ultra-comprehensive header file"""
        header_lines = [
            "#pragma once",
            "#ifndef RECONSTRUCTED_DLL_H",
            "#define RECONSTRUCTED_DLL_H",
            "",
            "// Auto-generated header for reconstructed DLL",
            f"// Original architecture: {self.architecture}",
            f"// Decompiler used: {self.decompiler_type.value}",
            f"// Functions found: {len(self.functions)}",
            f"// Structures found: {len(self.structures)}",
            "",
            "// Standard includes",
            "#include <windows.h>",
            "#include <stdint.h>",
            "#include <stdbool.h>",
            "",
            "// Compiler-specific macros",
            "#ifdef _MSC_VER",
            "    #define FORCE_INLINE __forceinline",
            "    #define ALIGN(x) __declspec(align(x))",
            "#elif defined(__GNUC__)",
            "    #define FORCE_INLINE inline __attribute__((always_inline))",
            "    #define ALIGN(x) __attribute__((aligned(x)))",
            "#else",
            "    #define FORCE_INLINE inline",
            "    #define ALIGN(x)",
            "#endif",
            "",
            "// Export/Import macros",
            "#ifdef BUILD_DLL",
            "    #define DLLAPI __declspec(dllexport)",
            "#else",
            "    #define DLLAPI __declspec(dllimport)",
            "#endif",
            "",
            "// Calling convention macros",
            "#define CDECL __cdecl",
            "#define STDCALL __stdcall",
            "#define FASTCALL __fastcall",
            ""
        ]
        
        # Add type definitions
        if self.typedefs:
            header_lines.extend([
                "// Type definitions",
                *[f"typedef {typedef};" for typedef in self.typedefs.values()],
                ""
            ])
        
        # Add structure definitions
        if self.structures:
            header_lines.extend([
                "// Structure definitions",
                ""
            ])
            for struct in self.structures.values():
                header_lines.append(f"typedef struct {struct.name} {{")
                for field in struct.fields.values():
                    pointer = "*" if field.is_pointer else ""
                    array = f"[{field.array_size}]" if field.array_size else ""
                    header_lines.append(f"    {field.type_info} {pointer}{field.name}{array};")
                header_lines.extend([f"}} {struct.name};", ""])
        
        # Add global variable declarations
        if self.global_variables:
            header_lines.extend([
                "// Global variables",
                *[f"extern {var.type_info} {var.name};" for var in self.global_variables.values()],
                ""
            ])
        
        # Add function declarations
        if self.functions:
            header_lines.extend([
                "// Function declarations",
                ""
            ])
            for func in self.functions.values():
                params = ", ".join([f"{p.type_info} {p.name}" for p in func.parameters]) or "void"
                export_macro = "DLLAPI " if func.is_exported else ""
                conv = func.calling_convention.value.replace("__", "").upper()
                header_lines.append(f"{export_macro}{func.return_type} {conv} {func.name}({params});")
        
        header_lines.extend([
            "",
            "#endif // RECONSTRUCTED_DLL_H"
        ])
        
        return "\n".join(header_lines)

    def generate_function_files(self) -> None:
        """Generate individual source files for each function"""
        header_name = "reconstructed_dll.h"
        
        for func in self.functions.values():
            file_lines = [
                f'#include "../include/{header_name}"',
                "",
                f"// Function: {func.name}",
                f"// Complexity: {func.complexity_score}",
                f"// Cyclomatic complexity: {func.cyclomatic_complexity}",
                f"// Dependencies: {', '.join(func.dependencies) if func.dependencies else 'None'}",
                ""
            ]
            
            # Add forward declarations for dependencies
            if func.dependencies:
                file_lines.extend([
                    "// Forward declarations",
                    *[f"{self.functions[dep].return_type} {dep}({', '.join([p.type_info + ' ' + p.name for p in self.functions[dep].parameters]) or 'void'});"
                      for dep in func.dependencies if dep in self.functions],
                    ""
                ])
            
            # Add the function implementation
            params = ", ".join([f"{p.type_info} {p.name}" for p in func.parameters]) or "void"
            file_lines.extend([
                f"{func.return_type} {func.calling_convention.value} {func.name}({params})",
                func.body
            ])
            
            # Write to file with UTF-8 encoding
            output_path = self.output_dir / 'src' / f"{func.name}.c"
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(file_lines))
            except Exception as e:
                logger.warning(f"Could not write function file {func.name}.c: {e}")
                # Try with error handling
                content = '\n'.join(file_lines)
                content = content.encode('utf-8', 'replace').decode('utf-8')
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(content)

    def generate_analysis_report(self) -> str:
        """Generate comprehensive analysis report"""
        report_lines = [
            "# DLL Reconstruction Analysis Report",
            f"Generated: {Path().cwd()}",
            "",
            "## Overview",
            f"- **Architecture**: {self.architecture}",
            f"- **Decompiler**: {self.decompiler_type.value}",
            f"- **Obfuscation detected**: {'Yes' if self.obfuscation_detected else 'No'}",
            f"- **Anti-debug detected**: {'Yes' if self.anti_debug_detected else 'No'}",
            "",
            "## Statistics",
            f"- **Functions processed**: {self.stats['functions_processed']}",
            f"- **Functions failed**: {self.stats['functions_failed']}",
            f"- **Structures found**: {len(self.structures)}",
            f"- **Global variables**: {len(self.global_variables)}",
            f"- **String literals**: {len(self.string_literals)}",
            f"- **Exported functions**: {len(self.exports)}",
            "",
            "## Exported Functions",
            *[f"- `{name}`" for name in sorted(self.exports)],
            "",
            "## Complex Functions (High Complexity Score)",
            *[f"- `{func.name}` (Score: {func.complexity_score}, Cyclomatic: {func.cyclomatic_complexity})"
              for func in sorted(self.functions.values(), key=lambda x: x.complexity_score, reverse=True)[:10]],
            "",
            "## Structures",
            *[f"- `{name}` ({len(struct.fields)} fields)" for name, struct in self.structures.items()],
            ""
        ]
        
        if self.compiler_info:
            report_lines.extend([
                "## Compiler Information",
                *[f"- **{key}**: {value}" for key, value in self.compiler_info.items()],
                ""
            ])
        
        return "\n".join(report_lines)

    def get_input_files(self) -> List[str]:
        """Get list of input files - compatible with old interface"""
        try:
            # Accept all files, not just C files (decompiler output might be .txt, .c, etc.)
            return [f.name for f in self.input_dir.iterdir() if f.is_file()]
        except Exception as e:
            # Fallback to os.listdir for compatibility
            try:
                input_dir_str = str(self.input_dir)  # Convert Path to string
                return [f for f in os.listdir(input_dir_str) 
                        if os.path.isfile(os.path.join(input_dir_str, f))]
            except Exception:
                return []

    def process_file(self, filename: str) -> Dict[str, Any]:
        """Main processing function - now with better Unicode handling"""
        try:
            logger.info(f"Processing file: {filename}")
            
            # Read input file with better encoding handling
            input_path = self.input_dir / filename
            content = None
            
            # Try different encodings
            encodings = ['utf-8', 'utf-16', 'latin1', 'cp1252']
            for encoding in encodings:
                try:
                    with open(input_path, 'r', encoding=encoding, errors='replace') as f:
                        content = f.read()
                    logger.info(f"Successfully read file with {encoding} encoding")
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                raise Exception("Could not read file with any supported encoding")
            
            # Reset state
            self._reset_state()
            
            # Comprehensive analysis
            self.decompiler_type = self.detect_decompiler(content)
            self.architecture = self.analyze_architecture(content)
            self.compiler_info = self.extract_compiler_info(content)
            self.obfuscation_detected = self.detect_obfuscation(content)
            self.anti_debug_detected = self.detect_anti_debug(content)
            
            # Extract all components
            self.extract_string_literals(content)
            self.extract_structures_comprehensive(content)
            self.extract_functions_comprehensive(content)
            
            # Generate output files
            self._generate_all_outputs()
            
            # Generate analysis report with better encoding handling
            try:
                analysis_report = self.generate_analysis_report()
                with open(self.output_dir / 'analysis' / 'report.md', 'w', encoding='utf-8') as f:
                    f.write(analysis_report)
            except Exception as e:
                logger.warning(f"Could not write analysis report: {e}")
            
            logger.info("Processing completed successfully")
            
            # Return data compatible with both old and new interfaces
            return {
                # Backward compatibility fields
                'filename': filename,
                'content': content[:10000] + "..." if len(content) > 10000 else content,  # Truncate for display
                'stats': {
                    'lines': len(content.splitlines()),
                    'characters': len(content),
                    'functions': len(self.functions),
                    'structures': len(self.structures)
                },
                
                # New comprehensive data
                'decompiler': self.decompiler_type.value,
                'architecture': self.architecture,
                'functions_count': len(self.functions),
                'exported_functions': list(self.exports),
                'structures_count': len(self.structures),
                'obfuscation_detected': self.obfuscation_detected,
                'anti_debug_detected': self.anti_debug_detected,
                'processing_stats': self.stats,
                'compiler_info': self.compiler_info,
                'extracted_functions': [f.name for f in self.functions.values()],
                'analysis_summary': {
                    'total_functions': len(self.functions),
                    'exported_functions': len(self.exports),
                    'complex_functions': len([f for f in self.functions.values() if f.complexity_score > 50]),
                    'has_inline_asm': any(f.inline_assembly for f in self.functions.values()),
                    'avg_complexity': sum(f.complexity_score for f in self.functions.values()) / len(self.functions) if self.functions else 0
                }
            }
            
        except Exception as e:
            logger.error(f"Error processing file {filename}: {e}")
            raise Exception(f"Error processing file {filename}: {str(e)}")

    def _reset_state(self):
        """Reset all internal state"""
        self.functions.clear()
        self.structures.clear()
        self.global_variables.clear()
        self.string_literals.clear()
        self.imports.clear()
        self.exports.clear()
        self.typedefs.clear()
        self.stats = {k: 0 for k in self.stats.keys()}

    def _generate_all_outputs(self):
        """Generate all output files"""
        # Generate header file
        header_content = self.generate_comprehensive_header()
        with open(self.output_dir / 'include' / 'reconstructed_dll.h', 'w', encoding='utf-8') as f:
            f.write(header_content)
        
        # Generate individual function files
        self.generate_function_files()
        
        # Generate Makefile
        makefile_content = self.generate_makefile()
        with open(self.output_dir / 'Makefile', 'w', encoding='utf-8') as f:
            f.write(makefile_content)
        
        # Generate resource files if strings found
        if self.string_literals:
            strings_header = "\n".join([
                "#pragma once",
                "// String literals extracted from binary",
                "",
                *[f'#define {name.upper()} "{self._escape_string(literal.value)}"' 
                  for name, literal in self.string_literals.items()],
                ""
            ])
            with open(self.output_dir / 'include' / 'strings.h', 'w', encoding='utf-8') as f:
                f.write(strings_header)

    def _escape_string(self, s: str) -> str:
        """Safely escape string literals for C headers"""
        try:
            # Replace problematic Unicode characters
            s = s.encode('ascii', 'replace').decode('ascii')
            # Escape quotes and backslashes
            s = s.replace('\\', '\\\\').replace('"', '\\"')
            return s
        except:
            return "INVALID_STRING"

# Create alias for backward compatibility
FileHandler = RobustDLLHandler
