import {CertificatInfo} from './certificat-info.model';

export class IssuedCertificate implements CertificatInfo {
  constructor(
    public commonName: string,
    public email: string | undefined,
    public country: string | undefined,
    public province: string | undefined,
    public city: string | undefined,
    public organisation: string | undefined,
    public organisationUnit: string | undefined,
    public expiresAt: Date,
    public serialNumber: string,
  ) {
  }

  public static hydrate(obj: IssuedCertificate) {
    return new IssuedCertificate(
      obj.commonName,
      obj.email,
      obj.country,
      obj.province,
      obj.city,
      obj.organisation,
      obj.organisationUnit,
      new Date(obj.expiresAt),
      obj.serialNumber,
    );
  }
}
