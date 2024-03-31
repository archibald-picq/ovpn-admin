
export class CreateCertificateBatchInfo {
  public commonName = '';
  public email = '';
  public country = '';
  public province = '';
  public city = '';
  public organisation = '';
  public organisationUnit = '';
  public staticAddress = '';
  public creationStatus?: 'ready' | 'exists' | 'invalid' | 'pending' | 'error';
  public lastError?: string;
  public skip = false;
  public processing = false;

  public static hydrate(obj: CreateCertificateBatchInfo): CreateCertificateBatchInfo {
    const target = new CreateCertificateBatchInfo();
    target.commonName = obj.commonName;
    target.email = obj.email;
    target.country = obj.country;
    target.province = obj.province;
    target.city = obj.city;
    target.organisation = obj.organisation;
    target.organisationUnit = obj.organisationUnit;
    target.staticAddress = obj.staticAddress;
    target.skip = obj.skip;
    return target;
  }
}
