"""Worker subpackage. Importing this package must NOT pull in any ida_* module;
those are imported only after idapro is activated, from within the modules that
need them (handlers, parts of idahelp/serve)."""
