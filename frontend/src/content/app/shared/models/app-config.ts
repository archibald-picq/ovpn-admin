
export class ServiceConfig {
    public url?: string;
}

export class AppConfig {
    public color?: string;
    public user?: Record<string, any>;
    public openvpn?: ServiceConfig;
    public peripherals?: ServiceConfig;

    constructor(raw?: Record<string, any>) {
        if (raw) {
            Object.assign(this, raw);
        }
    }
    public static parse(raw: Record<string, any>): AppConfig {
        return new AppConfig(raw);
    }
}