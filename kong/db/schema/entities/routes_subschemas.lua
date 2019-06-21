local routes_subschemas = {}


local http_subschema = {
  name = "http",
  fields = {
    { sources = { type = "set", len_eq = 0 } },
    { destinations = { type = "set", len_eq = 0 } },
  },
  entity_checkers = {
    at_least_one_of = { "methods", "hosts", "paths", "snis" },
    { conditional = { if_field = "protocols",
                      if_match = { elements = { type = "string", not_one_of = { "https" }}},
                      then_field = "snis",
                      then_match = { len_eq = 0 },
                      then_err = "'snis' can only be set when 'protocols' is 'https'",
                    }},
  },
}

local tcp_subschema = {
  name = "tcp",
  fields = {
    { methods = { type = "set", len_eq = 0, } },
    { hosts = { type = "array", --[[ elements = ..., ]] len_eq = 0 } },
    { paths = { type = "array", len_eq = 0 } },
  },
  entity_checkers = {
    at_least_one_of = { "sources", "destinations", "snis" },
    { conditional = { if_field = "protocols",
                      if_match = { elements = { type = "string", not_one_of = { "tls" }}},
                      then_field = "snis",
                      then_match = { len_eq = 0 },
                      then_err = "'snis' can only be set when 'protocols' is 'tls'",
                    }},
  },
}


function routes_subschemas.load()
  kong.db.routes.schema:new_subschema("http", http_subschema)
  kong.db.routes.schema:new_subschema("https", http_subschema)
  kong.db.routes.schema:new_subschema("tcp", tcp_subschema)
  kong.db.routes.schema:new_subschema("tls", tcp_subschema)
end


return routes_subschemas

