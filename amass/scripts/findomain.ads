name = "findomain"
type = "ext"

function vertical(ctx, domain)
        local cmd = "findomain -q -t " .. domain
        local data = assert(io.popen(cmd))
        for line in data:lines() do
                nrename(ctx, line)
        end
        data:close()
end