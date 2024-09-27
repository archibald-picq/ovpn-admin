import { Component } from '@angular/core';
import {AppConfigService} from '../../shared/services/app-config.service';
import {AppConfig} from '../../shared/models/app-config';

@Component({
    selector: 'bus-ui',
    templateUrl: './denied.component.html',
    styleUrls: ['../error.component.scss', './denied.component.scss'],
})
export class DeniedPageComponent {
  public appConfig: AppConfig;

  constructor(
    configService: AppConfigService,
  ) {
    this.appConfig = configService.get();
  }
}
