import cors from '@fastify/cors'
import { WebSocket } from '@fastify/websocket'
import spawn from 'child_process'
import fastify, { FastifyReply, FastifyRequest } from 'fastify'
import isValidDomain from 'is-valid-domain'
import { isIP } from 'net'
import { promises as dns } from 'dns'
import { z } from "zod"

const server = fastify()
server.register(cors, {
    origin: process.env.CORS_ORIGIN || "*"
})
server.register(import('@fastify/websocket'))
server.register(import('@fastify/rate-limit'), {
    max: 30,
    timeWindow: '1 minute'
})

const validateSubnet = (subnet: string) => {
    const ip = subnet.split('/')[0]
    const ipVersion = isIP(ip)
    const cidr = subnet.split('/')[1] as unknown as number
    if (isNaN(cidr)) {
        return false
    }
    if (subnet.split('/').length !== 2) {
        return false
    }
    if (ipVersion === 4) {
        return false
    }
    if (ipVersion === 6) {
        return cidr >= 0 && cidr <= 128
    }
    return false
}

server.get('/', async (request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(200).send({ "message": "https://github.com/vojkovic/confetti" })
})

server.register(async function (fastify) {
    fastify.get('/latency', { websocket: true }, async (connection: WebSocket, request: FastifyRequest) => {
        const remoteIp = request.headers['x-forwarded-for'] || request.socket.remoteAddress
        console.log(`[${new Date()}][LATENCY] websocket connected from ${remoteIp}`)
        connection.on('message', (message: string) => {
            connection.send(message.toString())
        })
        connection.on('close', () => {
            console.log(`[${new Date()}][LATENCY] websocket disconnected from ${remoteIp}`)
        })
    })
})

server.post('/lg', async (request: FastifyRequest, reply: FastifyReply) => {
    let validation
    try {
        validation = z.object({
            type: z.enum(["mtr", "traceroute", "ping", "bgp"]),
            target: z.string().trim(),
        }).parse(request.body)
    } catch (err) {
        return reply.status(400).send({ "error": err })
    }
    const remoteIp = request.headers['x-forwarded-for'] || request.socket.remoteAddress
    console.log(`[${new Date()}][LG] ${validation.type} ${validation.target} from ${remoteIp}`)

    const checkIPv6 = async (target: string): Promise<string | null> => {
        if (isIP(target) === 4) {
            return "IPv4 addresses are not allowed. Please provide an IPv6 address."
        }
        if (!isIP(target)) {
            try {
                const aaaaRecords = await dns.resolve6(target)
                if (!aaaaRecords || aaaaRecords.length === 0) {
                    return "The provided domain only resolves to IPv4 (A record). Please use a domain with an AAAA record for IPv6."
                }
            } catch (err) {
                return "Failed to resolve AAAA record for the domain. Ensure the domain has a valid IPv6 address."
            }
        }
        return null
    }

    switch (validation.type) {
        case "mtr":
            if (!(process.env.PINGTRACE_ENABLED === "true")) {
                return reply.status(400).send({ "error": "MTR is disabled" })
            }
            {
                const error = await checkIPv6(validation.target)
                if (error) {
                    return reply.status(400).send({ "error": error })
                }
                const mtr = spawn.spawnSync('mtr', ['-c', '5', '-r', '-w', '-b', validation.target])
                const output = mtr.stdout.toString() || mtr.stderr.toString()
                return reply.status(200).send({ "data": output })
            }

        case "traceroute":
            if (!(process.env.PINGTRACE_ENABLED === "true")) {
                return reply.status(400).send({ "error": "Traceroute is disabled" })
            }
            {
                const error = await checkIPv6(validation.target)
                if (error) {
                    return reply.status(400).send({ "error": error })
                }
                const traceroute = spawn.spawnSync('traceroute', ['-w', '1', '-q', '1', validation.target])
                const output = traceroute.stdout.toString() || traceroute.stderr.toString()
                return reply.status(200).send({ "data": output })
            }

        case "ping":
            if (!(process.env.PINGTRACE_ENABLED === "true")) {
                return reply.status(400).send({ "error": "Ping is disabled" })
            }
            {
                const error = await checkIPv6(validation.target)
                if (error) {
                    return reply.status(400).send({ "error": error })
                }
                // Spawn the ping command.
                const ping = spawn.spawnSync('ping', ['-c', '5', validation.target])
                const output = ping.stdout.toString() || ping.stderr.toString()
                return reply.status(200).send({ "data": output })
            }

        case "bgp":
            if (!(process.env.BGP_ENABLED === "true")) {
                return reply.status(400).send({ "error": "BGP is disabled" })
            }
            if (!isIP(validation.target) && !validateSubnet(validation.target)) {
                return reply.status(400).send({ "error": "Invalid IP/CIDR. Ensure it is in IPv6 format with a valid CIDR." })
            }
            const bgp = spawn.spawnSync('birdc', ['-r', 'sh', 'ro', 'all', 'for', validation.target])
            {
                const output = bgp.stdout.toString() || bgp.stderr.toString()
                return reply.status(200).send({ "data": output })
            }

        default:
            return reply.status(400).send({ "error": "Invalid type" })
    }
})

server.listen({ port: 33046, host: "::1" }, (err: any, address: string) => {
    if (err) {
        console.error(err)
        process.exit(1)
    }
    console.log(`Server listening at ${address}`)
})
