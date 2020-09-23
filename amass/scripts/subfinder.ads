name = "subfinder"
type = "ext"

function vertical(ctx, domain)
        local cmd = "./links/findomain -config /opt/autofindomain/subfinder_config.yaml -max-time 1 -nW -silent -d" .. domain
        local data = assert(io.popen(cmd))
        for line in data:lines() do
                nrename(ctx, line)
        end
        data:close()
end