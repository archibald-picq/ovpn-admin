
export class ServiceConfig {
  public url?: string;

  constructor(raw?: Record<string, any>) {
    this.url = raw?.url;
  }
}
