global ext_map: table[string] of string = {
    ["application/x-dosexec"] = "exe",
    ["text/plain"] = "txt",
    ["text/csv"] = "csv",
    ["text/javascript"] = "jscript",
    ["text/vcard"] = "vcard",
    ["image/jpeg"] = "jpg",
    ["image/png"] = "png",
    ["text/html"] = "html",
    ["application/json"] ="json",
    ["application/javascript"] = "js",
    ["application/pdf"] = "pdf",
    ["application/xml"] = "xml",
    ["application/zip"] = "zip",
    ["audio/mp4"] = "mp4",
    ["audio/mpeg"] = "mpeg",
    ["audio/flac"] = "flac",
    ["application/pgp-keys"] = "key",
    ["application/msword"] = "doc",
    ["application/msaccess"] = "mdb",
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
    ["application/vnd.ms-powerpoint"] = "ppt",
    ["application/vnd.ms-excel"] = "xls",
    ["application/java-archive"] = "jar",
    ["application/rar"] = "rar",
    ["application/zip"] = "zip",
    ["application/x-gtar"] = "tar",
    ["application/x-gtar-compressed"] = "tgz",
    ["image/x-icon"] = "ico",
    ["image/gif"] = "gif",
    ["text/x-src"] = "c",

} &default ="";

event file_new(f: fa_file)
    {
    local ext = "";

    if ( f?$mime_type )
        ext = ext_map[f$mime_type];

    local fname = fmt("%s-%s.%s", f$source, f$id, ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }
