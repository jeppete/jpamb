#!/usr/bin/env python3
"""
Debloater GUI - Visual tool for debloating analysis.

A Tkinter-based interface to visualize dead code detection across
source and bytecode analysis pipelines.
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
from pathlib import Path
import sys

import jpamb
from jpamb import jvm

# Add project root and solutions to path
PROJECT_ROOT = Path(__file__).parent.parent
SOLUTIONS_DIR = Path(__file__).parent
COMPONENTS_DIR = Path(__file__).parent / "components"
for p in [PROJECT_ROOT, SOLUTIONS_DIR, COMPONENTS_DIR]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from debloater import Debloater, BatchDebloater, BatchResult  # noqa: E402



class DebloaterGUI:
    """Main GUI window for the debloater tool."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Debloater - Dead Code Detection Tool")
        self.root.geometry("1000x700")
        
        # State
        self.suite = jpamb.Suite()
        self.debloater = None
        self.batch_debloater = None
        self.current_class = None
        self.current_source = None
        self.batch_mode = False
        self.batch_results = None
        self.batch_file_map = {}  # Maps tree item IDs to (file_path, combined_result)
        
        # Setup UI
        self.setup_ui()
        
    def setup_ui(self):
        """Create the main UI layout."""
        
        # ============ TOP: Toolbar ============
        toolbar = ttk.Frame(self.root, padding="8")
        toolbar.pack(fill=tk.X)
        
        # Mode selection (left side)
        mode_section = ttk.Frame(toolbar)
        mode_section.pack(side=tk.LEFT)
        
        ttk.Label(mode_section, text="Mode:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 8))
        self.mode_var = tk.StringVar(value="single")
        ttk.Radiobutton(mode_section, text="Single File", variable=self.mode_var, 
                       value="single", command=self.toggle_mode).pack(side=tk.LEFT)
        ttk.Radiobutton(mode_section, text="Batch", variable=self.mode_var, 
                       value="batch", command=self.toggle_mode).pack(side=tk.LEFT, padx=(8, 0))
        
        # Action buttons (right side)
        btn_section = ttk.Frame(toolbar)
        btn_section.pack(side=tk.RIGHT)
        
        ttk.Button(btn_section, text="Clear", command=self.clear_results).pack(side=tk.RIGHT, padx=4)
        self.analyze_btn = ttk.Button(btn_section, text="🔍 Analyze", command=self.run_analysis)
        self.analyze_btn.pack(side=tk.RIGHT, padx=4)
        
        # ============ INPUT SECTION ============
        input_container = ttk.Frame(self.root, padding="8")
        input_container.pack(fill=tk.X)
        
        # Single file inputs (shown by default)
        self.single_frame = ttk.LabelFrame(input_container, text="File Selection", padding="8")
        self.single_frame.pack(fill=tk.X)
        
        # Class input row
        class_row = ttk.Frame(self.single_frame)
        class_row.pack(fill=tk.X, pady=2)
        ttk.Label(class_row, text="Class:", width=8).pack(side=tk.LEFT)
        self.class_entry = ttk.Entry(class_row)
        self.class_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.class_entry.insert(0, "jpamb.cases.Simple")
        
        # Source input row
        source_row = ttk.Frame(self.single_frame)
        source_row.pack(fill=tk.X, pady=2)
        ttk.Label(source_row, text="Source:", width=8).pack(side=tk.LEFT)
        self.source_entry = ttk.Entry(source_row)
        self.source_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.source_entry.insert(0, "src/main/java/jpamb/cases/Simple.java")
        ttk.Button(source_row, text="Browse...", command=self.browse_source).pack(side=tk.RIGHT)
        
        # Batch directory input (hidden by default)
        self.batch_frame = ttk.LabelFrame(input_container, text="Directory Selection", padding="8")
        
        dir_row = ttk.Frame(self.batch_frame)
        dir_row.pack(fill=tk.X, pady=2)
        ttk.Label(dir_row, text="Directory:", width=8).pack(side=tk.LEFT)
        self.dir_entry = ttk.Entry(dir_row)
        self.dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.dir_entry.insert(0, "src/main/java/jpamb/cases")
        ttk.Button(dir_row, text="Browse...", command=self.browse_directory).pack(side=tk.RIGHT)
        
        # ============ OPTIONS SECTION ============
        options_container = ttk.Frame(self.root, padding="8")
        options_container.pack(fill=tk.X)
        
        options_frame = ttk.LabelFrame(options_container, text="Analysis Options", padding="8")
        options_frame.pack(fill=tk.X)
        
        options_row = ttk.Frame(options_frame)
        options_row.pack(fill=tk.X)
        
        # Abstract interpreter toggle
        self.abstract_interp_var = tk.BooleanVar(value=True)
        self.abstract_interp_cb = ttk.Checkbutton(
            options_row, 
            text="🧠 Abstract Interpreter",
            variable=self.abstract_interp_var,
            command=self.on_abstract_toggle
        )
        self.abstract_interp_cb.pack(side=tk.LEFT, padx=(0, 16))
        
        # Domain selection
        self.domain_frame = ttk.Frame(options_row)
        self.domain_frame.pack(side=tk.LEFT)
        
        ttk.Label(self.domain_frame, text="Domain:").pack(side=tk.LEFT, padx=(0, 4))
        self.domain_var = tk.StringVar(value="product")
        self.domain_combo = ttk.Combobox(
            self.domain_frame, 
            textvariable=self.domain_var,
            values=["sign", "interval", "product"],
            state="readonly",
            width=10
        )
        self.domain_combo.pack(side=tk.LEFT)
        
        # Tooltip-style label
        self.domain_info = ttk.Label(options_row, text="(Product = Interval + Nullness)", 
                                    font=("Arial", 9), foreground="gray")
        self.domain_info.pack(side=tk.LEFT, padx=8)
        
        # ============ STATISTICS BAR ============
        stats_container = ttk.Frame(self.root, padding="8")
        stats_container.pack(fill=tk.X)
        
        stats_frame = ttk.LabelFrame(stats_container, text="Statistics", padding="8")
        stats_frame.pack(fill=tk.X)
        
        # Use a horizontal row with evenly spaced stat cards
        stats_row = ttk.Frame(stats_frame)
        stats_row.pack(fill=tk.X)
        
        # Configure grid columns to expand equally
        for i in range(5):
            stats_row.columnconfigure(i, weight=1)
        
        # Stat card helper function
        def create_stat_card(parent, col, label_text, initial_value, fg_color=None):
            card = ttk.Frame(parent)
            card.grid(row=0, column=col, padx=8, sticky=tk.NSEW)
            
            value_label = ttk.Label(card, text=initial_value, font=("Arial", 14, "bold"))
            if fg_color:
                value_label.config(foreground=fg_color)
            value_label.pack()
            
            ttk.Label(card, text=label_text, font=("Arial", 9), foreground="gray").pack()
            return value_label
        
        # Create stat cards
        self.source_count_label = create_stat_card(stats_row, 0, "Source Findings", "0")
        self.bytecode_count_label = create_stat_card(stats_row, 1, "Dead Instructions", "0 / 0")
        self.methods_count_label = create_stat_card(stats_row, 2, "Unreachable Methods", "0")
        self.verified_count_label = create_stat_card(stats_row, 3, "Verified (Both)", "0", "darkgreen")
        self.total_lines_label = create_stat_card(stats_row, 4, "Total Dead Lines", "0", "darkred")
        
        # Progress bar
        self.progress = ttk.Progressbar(stats_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(8, 0))
        
        # ============ BOTTOM: Results Panel ============
        results_frame = ttk.Frame(self.root)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create PanedWindow for split view
        self.paned_window = ttk.PanedWindow(results_frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Left pane: Source code viewer
        source_frame = ttk.LabelFrame(self.paned_window, text="Source Code", padding="5")
        self.paned_window.add(source_frame, weight=1)
        
        # File indicator for batch mode
        self.file_label_frame = ttk.Frame(source_frame)
        self.file_label_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(self.file_label_frame, text="File:", font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=5)
        self.current_file_label = ttk.Label(self.file_label_frame, text="No file loaded", 
                                           font=("Arial", 9), foreground="gray")
        self.current_file_label.pack(side=tk.LEFT, padx=5)
        
        # Create source code text widget with line numbers
        code_container = ttk.Frame(source_frame)
        code_container.pack(fill=tk.BOTH, expand=True)
        
        # Line numbers
        self.line_numbers = tk.Text(code_container, width=5, padx=5, takefocus=0,
                                    border=0, background='#2b2b2b', foreground='#888888',
                                    state='disabled', font=('Courier', 10))
        self.line_numbers.pack(side=tk.LEFT, fill=tk.Y)
        
        # Source code text with scrollbar
        code_scroll_frame = ttk.Frame(code_container)
        code_scroll_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        code_vsb = ttk.Scrollbar(code_scroll_frame, orient="vertical")
        code_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.source_text = tk.Text(code_scroll_frame, wrap=tk.NONE, 
                                   yscrollcommand=code_vsb.set,
                                   font=('Courier', 10),
                                   background='#2b2b2b', foreground='#e0e0e0',
                                   insertbackground='white',
                                   state='disabled')
        self.source_text.pack(fill=tk.BOTH, expand=True)
        code_vsb.config(command=self.source_text.yview)
        
        # Sync line numbers with source code scrolling
        self.source_text.config(yscrollcommand=lambda *args: [
            code_vsb.set(*args),
            self.line_numbers.yview_moveto(args[0])
        ])
        
        # Configure tags for highlighting (adjusted for dark background)
        self.source_text.tag_config('dead_code', background='#663333', foreground='#ffaaaa')
        self.source_text.tag_config('dead_source', background='#664433', foreground='#ffcc99')
        self.source_text.tag_config('dead_bytecode', background='#334466', foreground='#99ccff')
        self.source_text.tag_config('current_line', background='#555533', foreground='#ffff99')
        
        # Add legend
        legend_frame = ttk.Frame(source_frame)
        legend_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(legend_frame, text="Legend:", font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=5)
        
        # Both pipelines - verified
        both_label = tk.Label(legend_frame, text=" ✅ Verified ", bg='#663333', fg='#ffaaaa', 
                             relief=tk.RAISED, padx=3, font=('Courier', 8))
        both_label.pack(side=tk.LEFT, padx=2)
        
        # Source only
        source_label = tk.Label(legend_frame, text=" Source ", bg='#664433', fg='#ffcc99',
                               relief=tk.RAISED, padx=3, font=('Courier', 8))
        source_label.pack(side=tk.LEFT, padx=2)
        
        # Bytecode only
        bytecode_label = tk.Label(legend_frame, text=" Bytecode ", bg='#334466', fg='#99ccff',
                                 relief=tk.RAISED, padx=3, font=('Courier', 8))
        bytecode_label.pack(side=tk.LEFT, padx=2)
        
        # Selected
        selected_label = tk.Label(legend_frame, text=" Selected ", bg='#555533', fg='#ffff99',
                                relief=tk.RAISED, padx=3, font=('Courier', 8))
        selected_label.pack(side=tk.LEFT, padx=2)
        
        # Right pane: Notebook for findings
        findings_frame = ttk.LabelFrame(self.paned_window, text="Analysis Results", padding="5")
        self.paned_window.add(findings_frame, weight=1)
        
        # Notebook for different views
        self.notebook = ttk.Notebook(findings_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Tab 1: Combined Results
        self.combined_tab = self.create_results_tab("Combined")
        self.notebook.add(self.combined_tab, text="📋 Combined Results")
        
        # Tab 2: Source Analysis
        self.source_tab = self.create_results_tab("Source")
        self.notebook.add(self.source_tab, text="📝 Source Analysis")
        
        # Tab 3: Bytecode Analysis
        self.bytecode_tab = self.create_results_tab("Bytecode")
        self.notebook.add(self.bytecode_tab, text="🔍 Bytecode Analysis")
        
        # Tab 4: Log
        self.log_tab = scrolledtext.ScrolledText(self.notebook, wrap=tk.WORD, 
                                                 height=15, font=("Courier", 9))
        self.notebook.add(self.log_tab, text="📄 Log")
        
        # ============ BOTTOM: Status Bar ============
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
    def create_results_tab(self, name):
        """Create a scrolled text widget for results."""
        frame = ttk.Frame(self.notebook)
        
        # Tree view for structured results
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # TreeView
        tree = ttk.Treeview(tree_frame, 
                           columns=("Line", "Type", "Message"),
                           show="tree headings",
                           yscrollcommand=vsb.set,
                           xscrollcommand=hsb.set)
        
        tree.heading("#0", text="Source")
        tree.heading("Line", text="Line")
        tree.heading("Type", text="Type")
        tree.heading("Message", text="Message")
        
        tree.column("#0", width=100)
        tree.column("Line", width=60, anchor=tk.CENTER)
        tree.column("Type", width=150)
        tree.column("Message", width=400)
        
        tree.pack(fill=tk.BOTH, expand=True)
        
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)
        
        # Store tree reference
        setattr(self, f"{name.lower()}_tree", tree)
        
        # Bind click event to jump to line
        tree.bind('<ButtonRelease-1>', lambda event: self.on_tree_click(event, tree))
        
        return frame
    
    def browse_source(self):
        """Open file dialog to select source file."""
        filename = filedialog.askopenfilename(
            title="Select Java Source File",
            filetypes=[("Java files", "*.java"), ("All files", "*.*")]
        )
        if filename:
            self.source_entry.delete(0, tk.END)
            self.source_entry.insert(0, filename)
    
    def browse_directory(self):
        """Open dialog to select directory for batch processing."""
        dirname = filedialog.askdirectory(
            title="Select Directory Containing Java Files"
        )
        if dirname:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, dirname)
    
    def toggle_mode(self):
        """Toggle between single file and batch mode."""
        mode = self.mode_var.get()
        self.batch_mode = (mode == "batch")
        
        if self.batch_mode:
            # Hide single file inputs, show batch inputs
            self.single_frame.pack_forget()
            self.batch_frame.pack(fill=tk.X)
        else:
            # Hide batch inputs, show single file inputs
            self.batch_frame.pack_forget()
            self.single_frame.pack(fill=tk.X)
    
    def on_abstract_toggle(self):
        """Handle abstract interpreter toggle."""
        enabled = self.abstract_interp_var.get()
        
        # Enable/disable domain selection
        if enabled:
            self.domain_combo.config(state="readonly")
            self.domain_info.config(foreground="gray")
        else:
            self.domain_combo.config(state="disabled")
            self.domain_info.config(foreground="lightgray")
    
    def log(self, message, level="INFO"):
        """Add a message to the log tab."""
        self.log_tab.insert(tk.END, f"[{level}] {message}\n")
        self.log_tab.see(tk.END)
        self.root.update()
    
    def update_status(self, message):
        """Update status bar."""
        self.status_bar.config(text=message)
        self.root.update()
    
    def clear_results(self):
        """Clear all results and reset UI."""
        # Clear trees
        for tree_name in ['combined_tree', 'source_tree', 'bytecode_tree']:
            tree = getattr(self, tree_name)
            for item in tree.get_children():
                tree.delete(item)
        
        # Clear log
        self.log_tab.delete(1.0, tk.END)
        
        # Clear source code viewer
        self.source_text.config(state='normal')
        self.source_text.delete(1.0, tk.END)
        self.source_text.config(state='disabled')
        
        self.line_numbers.config(state='normal')
        self.line_numbers.delete(1.0, tk.END)
        self.line_numbers.config(state='disabled')
        
        # Reset file label
        self.current_file_label.config(text="No file loaded", foreground="gray")
        
        # Clear batch mappings
        self.batch_file_map.clear()
        
        # Reset stats
        self.source_count_label.config(text="0")
        self.bytecode_count_label.config(text="0 / 0 (0.0%)")
        self.methods_count_label.config(text="0")
        self.verified_count_label.config(text="0")
        self.total_lines_label.config(text="0")
        
        self.update_status("Cleared")
    
    def load_source_code(self, source_file: Path):
        """Load and display source code in the viewer."""
        try:
            with open(source_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Update file label
            self.current_file_label.config(text=str(source_file), foreground="black")
            
            # Enable editing temporarily
            self.source_text.config(state='normal')
            self.line_numbers.config(state='normal')
            
            # Clear existing content
            self.source_text.delete(1.0, tk.END)
            self.line_numbers.delete(1.0, tk.END)
            
            # Add source code
            self.source_text.insert(1.0, content)
            
            # Add line numbers
            num_lines = int(self.source_text.index('end-1c').split('.')[0])
            line_nums = '\n'.join(str(i) for i in range(1, num_lines + 1))
            self.line_numbers.insert(1.0, line_nums)
            
            # Disable editing
            self.source_text.config(state='disabled')
            self.line_numbers.config(state='disabled')
            
        except Exception as e:
            self.log(f"Error loading source code: {e}", "ERROR")
            self.current_file_label.config(text=f"Error loading {source_file.name}", foreground="red")
    
    def highlight_dead_code(self, dead_lines: dict):
        """
        Highlight dead code lines in the source viewer.
        
        Args:
            dead_lines: dict mapping line numbers to list of findings
        """
        self.source_text.config(state='normal')
        
        # Clear existing highlights
        self.source_text.tag_remove('dead_code', 1.0, tk.END)
        self.source_text.tag_remove('dead_source', 1.0, tk.END)
        self.source_text.tag_remove('dead_bytecode', 1.0, tk.END)
        
        # Highlight each dead line
        for line_num, findings in dead_lines.items():
            # Determine highlight color based on source
            # Check if explicitly marked as 'both'
            is_both = any(f.get('source') == 'both' for f in findings)
            has_source = any(f.get('source') == 'source_analysis' for f in findings)
            has_bytecode = any(f.get('source') == 'bytecode_analysis' for f in findings)
            
            if is_both or (has_source and has_bytecode):
                tag = 'dead_code'  # Both - dark red
            elif has_source:
                tag = 'dead_source'  # Source only - dark orange
            else:
                tag = 'dead_bytecode'  # Bytecode only - dark blue
            
            # Highlight the line
            start = f"{line_num}.0"
            end = f"{line_num}.end"
            self.source_text.tag_add(tag, start, end)
        
        self.source_text.config(state='disabled')
    
    def jump_to_line(self, line_num: int):
        """
        Jump to and highlight a specific line in the source viewer.
        
        Args:
            line_num: Line number to jump to
        """
        # Remove previous current line highlight
        self.source_text.tag_remove('current_line', 1.0, tk.END)
        
        # Add current line highlight
        start = f"{line_num}.0"
        end = f"{line_num}.end"
        self.source_text.tag_add('current_line', start, end)
        
        # Scroll to make the line visible
        self.source_text.see(start)
        
        # Also scroll line numbers
        self.line_numbers.see(start)
    
    def on_tree_click(self, event, tree):
        """Handle click on tree item to jump to that line or load file in batch mode."""
        # Get selected item
        selection = tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = tree.item(item, 'values')
        
        # Check if this is a batch mode item
        if item in self.batch_file_map:
            file_path, combined = self.batch_file_map[item]
            
            # Load the source file
            if file_path.exists():
                self.load_source_code(file_path)
                self.highlight_dead_code(combined.by_line)
                
                # If there's a line number, jump to it
                if values and values[0]:
                    try:
                        line_num = int(values[0])
                        self.jump_to_line(line_num)
                    except (ValueError, IndexError):
                        pass
            return
        
        # Single file mode: just jump to line
        if values and values[0]:
            try:
                line_num = int(values[0])
                self.jump_to_line(line_num)
            except (ValueError, IndexError):
                pass  # Not a valid line number
    
    def run_analysis(self):
        """Run the debloating analysis."""
        if self.batch_mode:
            self.run_batch_analysis()
        else:
            self.run_single_analysis()
    
    def run_single_analysis(self):
        """Run analysis on a single file."""
        # Get inputs
        class_str = self.class_entry.get().strip()
        source_str = self.source_entry.get().strip()
        
        if not class_str:
            self.log("Error: Please enter a class name", "ERROR")
            return
        
        try:
            # Clear previous results
            self.clear_results()
            
            # Update UI
            self.analyze_btn.config(state='disabled')
            self.progress.start()
            self.update_status("Analyzing...")
            
            # Parse class name
            parts = class_str.split(".")
            classname = jvm.ClassName("/".join(parts))
            
            source_file = Path(source_str) if source_str else None
            
            self.log(f"Analyzing class: {class_str}")
            if source_file:
                self.log(f"Source file: {source_file}")
                # Load source code into viewer
                if source_file.exists():
                    self.load_source_code(source_file)
                else:
                    self.log(f"Warning: Source file not found: {source_file}", "WARNING")
            
            # Create debloater with custom logging and settings
            enable_abstract = self.abstract_interp_var.get()
            domain = self.domain_var.get()
            self.debloater = DebloaterWithGUILogging(
                self.suite, self, 
                enable_abstract_interpreter=enable_abstract,
                abstract_domain=domain
            )
            
            # Run analysis
            self.debloater.analyze_class(classname, source_file, verbose=False)
            
            # Display results
            self.display_results()
            
            self.log("Analysis complete!", "SUCCESS")
            self.update_status("Analysis complete")
            
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
            self.update_status(f"Error: {e}")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
        
        finally:
            self.progress.stop()
            self.analyze_btn.config(state='normal')
    
    def run_batch_analysis(self):
        """Run batch analysis on a directory of files."""
        dir_str = self.dir_entry.get().strip()
        
        if not dir_str:
            self.log("Error: Please select a directory", "ERROR")
            return
        
        directory = Path(dir_str)
        if not directory.exists():
            self.log(f"Error: Directory not found: {directory}", "ERROR")
            return
        
        try:
            # Clear previous results
            self.clear_results()
            
            # Update UI
            self.analyze_btn.config(state='disabled')
            self.progress.start()
            self.update_status("Finding Java files...")
            
            # Create batch debloater with settings
            enable_abstract = self.abstract_interp_var.get()
            domain = self.domain_var.get()
            batch_debloater = BatchDebloaterWithGUILogging(
                self.suite, self,
                enable_abstract_interpreter=enable_abstract,
                abstract_domain=domain
            )
            
            self.log(f"Scanning directory: {directory}")
            files_to_analyze = batch_debloater.find_java_files(directory)
            
            if not files_to_analyze:
                self.log("No Java files found in directory", "WARNING")
                self.update_status("No files found")
                return
            
            self.log(f"Found {len(files_to_analyze)} Java file(s)")
            self.update_status(f"Analyzing {len(files_to_analyze)} files...")
            
            # Run batch analysis
            batch_result = batch_debloater.analyze_files(files_to_analyze, show_progress=True)
            self.batch_results = batch_result
            
            # Display batch results
            self.display_batch_results(batch_result)
            
            self.log(f"Batch analysis complete! Processed {batch_result.successful_files}/{batch_result.total_files} files", "SUCCESS")
            self.update_status("Batch analysis complete")
            
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
            self.update_status(f"Error: {e}")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
        
        finally:
            self.progress.stop()
            self.analyze_btn.config(state='normal')
    
    def display_results(self):
        """Display analysis results in the UI."""
        if not self.debloater or not self.debloater.results:
            return
        
        results = self.debloater.results
        
        # Update statistics
        source_result = results.get('source')
        bytecode_result = results.get('bytecode')
        combined = results.get('combined')
        
        if source_result:
            self.source_count_label.config(text=str(len(source_result.findings)))
            self.populate_source_tree(source_result)
        
        if bytecode_result:
            dead_count = bytecode_result.get_dead_instruction_count()
            total_count = bytecode_result.total_instructions
            percentage = bytecode_result.get_debloat_percentage()
            self.bytecode_count_label.config(text=f"{dead_count} / {total_count} ({percentage:.1f}%)")
            self.methods_count_label.config(text=str(len(bytecode_result.unreachable_methods)))
            self.populate_bytecode_tree(bytecode_result)
        
        if combined:
            # Count verified by both
            both_count = sum(1 for s in combined.suggestions if s.get('source') == 'both')
            self.verified_count_label.config(text=str(both_count))
            self.total_lines_label.config(text=str(combined.total_dead_lines))
            self.populate_combined_tree(combined)
            # Highlight dead code in source viewer
            self.highlight_dead_code(combined.by_line)
    
    def display_batch_results(self, batch_result: BatchResult):
        """Display batch analysis results in the UI."""
        # Clear previous batch file mappings
        self.batch_file_map.clear()
        
        # Update overall statistics
        self.total_lines_label.config(text=str(batch_result.total_dead_lines))
        self.verified_count_label.config(text=str(batch_result.total_verified))
        self.source_count_label.config(text=str(batch_result.total_source_only))
        
        # Format instruction count with percentage
        percentage = batch_result.get_debloat_percentage()
        self.bytecode_count_label.config(
            text=f"{batch_result.total_dead_instructions} / {batch_result.total_instructions} ({percentage:.1f}%)"
        )
        
        # Populate combined tree with file-by-file results
        tree = self.combined_tree
        
        for file_path, combined in batch_result.results_by_file.items():
            file_name = Path(file_path).name
            
            # Add file as top-level parent
            verified = sum(1 for s in combined.suggestions if s.get('source') == 'both')
            file_id = tree.insert("", "end", text=f"📄 {file_name}",
                                 values=("", f"{combined.total_dead_lines} dead lines", 
                                       f"Verified: {verified}"))
            
            # Store mapping for this file
            self.batch_file_map[file_id] = (Path(file_path), combined)
            
            # Add dead lines under each file
            for line in sorted(combined.by_line.keys())[:20]:  # Limit to first 20 per file
                suggestions = combined.by_line[line]
                
                for sugg in suggestions:
                    if sugg['source'] == 'both':
                        icon = "✅"
                    elif sugg['source'] == 'source_analysis':
                        icon = "📝"
                    else:
                        icon = "🔍"
                    
                    child_id = tree.insert(file_id, "end", text=icon,
                                          values=(line, sugg['type'], sugg['message']))
                    # Store parent file mapping for children too
                    self.batch_file_map[child_id] = (Path(file_path), combined)
            
            if len(combined.by_line) > 20:
                more_id = tree.insert(file_id, "end", text="...",
                                     values=("", "", f"and {len(combined.by_line) - 20} more lines"))
                self.batch_file_map[more_id] = (Path(file_path), combined)
        
        # Add errors if any
        if batch_result.errors_by_file:
            error_id = tree.insert("", "end", text="❌ Errors",
                                  values=("", f"{len(batch_result.errors_by_file)} files", ""))
            for file_path, error in batch_result.errors_by_file.items():
                file_name = Path(file_path).name
                tree.insert(error_id, "end", text="",
                          values=("", file_name, error))
    
    def populate_combined_tree(self, combined):
        """Populate the combined results tree."""
        tree = self.combined_tree
        
        # Group by line
        for line in sorted(combined.by_line.keys()):
            suggestions = combined.by_line[line]
            
            # Add line as parent
            line_id = tree.insert("", "end", text=f"Line {line}", 
                                 values=(line, "", ""))
            
            # Add suggestions as children
            for sugg in suggestions:
                if sugg['source'] == 'both':
                    icon = "✅"  # Both pipelines verified
                elif sugg['source'] == 'source_analysis':
                    icon = "📝"
                else:
                    icon = "🔍"
                tree.insert(line_id, "end", text=icon,
                          values=(line, sugg['type'], sugg['message']))
    
    def populate_source_tree(self, source_result):
        """Populate the source analysis tree."""
        tree = self.source_tree
        
        for finding in source_result.findings:
            tree.insert("", "end", text="📝",
                       values=(finding.line, finding.kind, finding.message))
    
    def populate_bytecode_tree(self, bytecode_result):
        """Populate the bytecode analysis tree."""
        tree = self.bytecode_tree
        
        # Add unreachable methods
        if bytecode_result.unreachable_methods:
            unreachable_id = tree.insert("", "end", text="Unreachable Methods",
                                        values=("", "", f"{len(bytecode_result.unreachable_methods)} methods"))
            for method in sorted(bytecode_result.unreachable_methods):
                tree.insert(unreachable_id, "end", text="🔍",
                           values=("", "unreachable", method))
        
        # Add dead instructions by method
        for method, offsets in sorted(bytecode_result.dead_instructions.items()):
            method_id = tree.insert("", "end", text=method,
                                   values=("", "dead_instructions", f"{len(offsets)} offsets"))
            for offset in sorted(offsets):
                tree.insert(method_id, "end", text="🔍",
                           values=("", "dead_code", f"offset {offset}"))


class DebloaterWithGUILogging(Debloater):
    """Debloater that logs to GUI instead of console."""
    
    def __init__(self, suite, gui, enable_abstract_interpreter=True, abstract_domain="product"):
        super().__init__(suite, enable_abstract_interpreter, abstract_domain)
        self.gui = gui
    
    def analyze_class(self, classname, source_file=None, verbose=False):
        """Override to add GUI logging."""
        self.gui.log("="*50)
        self.gui.log(f"DEBLOATER ANALYSIS: {classname}")
        self.gui.log("="*50)
        
        # Run source pipeline
        if source_file and source_file.exists():
            self.gui.log("\n[Pipeline 1] Source Analysis")
            self.gui.update_status("Running source analysis...")
            source_result = self.run_source_pipeline(source_file)
            self.results['source'] = source_result
            self.gui.log(f"  Found {len(source_result.findings)} source findings")
        else:
            self.gui.log("\n[Pipeline 1] Source Analysis: Skipped")
            self.results['source'] = self.__class__.__bases__[0].run_source_pipeline(self, source_file)
        
        # Run bytecode pipeline
        self.gui.log("\n[Pipeline 2] Bytecode Analysis")
        self.gui.update_status("Running bytecode analysis...")
        bytecode_result = self.run_bytecode_pipeline(classname)
        self.results['bytecode'] = bytecode_result
        
        total_dead = sum(len(offsets) for offsets in bytecode_result.dead_instructions.values())
        self.gui.log(f"  Found {len(bytecode_result.unreachable_methods)} unreachable methods")
        self.gui.log(f"  Found {total_dead} dead instructions")
        
        # Verify suspected unused imports with bytecode
        source_result = self.results.get('source')
        if source_result and source_result.suspected_unused_imports:
            self.gui.log("\n[Verification] Checking unused imports with bytecode")
            self.gui.update_status("Verifying unused imports...")
            confirmed_unused = self.verify_unused_imports_with_bytecode(
                classname,
                source_result.suspected_unused_imports
            )
            
            # Add confirmed unused imports as findings
            for import_path, line_num in source_result.suspected_unused_imports.items():
                if import_path in confirmed_unused:
                    class_name = import_path.split("/")[-1]
                    source_result.add_finding(
                        line=line_num,
                        kind="unused_import",
                        message=f"Import '{class_name}' is never used (verified by bytecode); candidate for removal.",
                        confidence="high",
                        verified_by_bytecode=True,  # Mark as verified!
                        import_path=import_path
                    )
                    self.gui.log(f"  ✓ Confirmed unused: {import_path}")
                else:
                    self.gui.log(f"  ✗ Actually used: {import_path}")
        
        # Map bytecode to source
        self.gui.log("\n[Mapping] Bytecode → Source")
        self.gui.update_status("Mapping bytecode to source...")
        mapped_bytecode = self.map_bytecode_to_source(classname, bytecode_result)
        self.results['bytecode_mapped'] = mapped_bytecode
        self.gui.log(f"  Mapped to {len(mapped_bytecode.dead_lines)} source lines")
        
        # Combine results
        self.gui.log("\n[Combine] Merging results")
        self.gui.update_status("Combining results...")
        combined = self.combine_results(self.results['source'], mapped_bytecode)
        self.results['combined'] = combined
        self.gui.log(f"  {len(combined.suggestions)} total suggestions")
        self.gui.log(f"  {combined.total_dead_lines} lines with dead code")


class BatchDebloaterWithGUILogging(BatchDebloater):
    """Batch debloater that logs to GUI instead of console."""
    
    def __init__(self, suite, gui, enable_abstract_interpreter=True, abstract_domain="product"):
        super().__init__(suite)
        self.gui = gui
        # Replace the internal debloater with GUI-logging version
        self.debloater = DebloaterWithGUILogging(
            suite, gui, 
            enable_abstract_interpreter, 
            abstract_domain
        )
    
    def analyze_files(self, files, show_progress=True):
        """Override to add GUI logging and progress tracking."""
        from debloater import BatchResult
        
        batch_result = BatchResult()
        batch_result.total_files = len(files)
        
        self.gui.log("="*50)
        self.gui.log(f"BATCH ANALYSIS: {len(files)} files")
        self.gui.log("="*50)
        
        for idx, (source_file, classname) in enumerate(files, 1):
            self.gui.log(f"\n[{idx}/{len(files)}] {source_file.name}")
            self.gui.log("-" * 50)
            self.gui.update_status(f"Analyzing {idx}/{len(files)}: {source_file.name}")
            
            try:
                # Analyze this file
                self.debloater.analyze_class(classname, source_file, verbose=False)
                
                # Get results
                combined = self.debloater.results.get('combined')
                bytecode_result = self.debloater.results.get('bytecode')
                
                if combined:
                    batch_result.successful_files += 1
                    batch_result.results_by_file[str(source_file)] = combined
                    batch_result.total_dead_lines += combined.total_dead_lines
                    
                    # Count by confidence
                    verified = sum(1 for s in combined.suggestions if s.get('source') == 'both')
                    source_only = sum(1 for s in combined.suggestions if s.get('source') == 'source_analysis')
                    bytecode_only = sum(1 for s in combined.suggestions if s.get('source') == 'bytecode_analysis')
                    
                    batch_result.total_verified += verified
                    batch_result.total_source_only += source_only
                    batch_result.total_bytecode_only += bytecode_only
                    
                    # Track instruction counts
                    if bytecode_result:
                        batch_result.total_instructions += bytecode_result.total_instructions
                        batch_result.total_dead_instructions += bytecode_result.get_dead_instruction_count()
                    
                    self.gui.log(f"  ✓ {combined.total_dead_lines} dead lines (Verified: {verified})")
                
            except Exception as e:
                batch_result.failed_files += 1
                batch_result.errors_by_file[str(source_file)] = str(e)
                self.gui.log(f"  ✗ Error: {e}", "ERROR")
        
        return batch_result


def main():
    """Launch the GUI."""
    root = tk.Tk()
    app = DebloaterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

