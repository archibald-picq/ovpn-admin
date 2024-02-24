import { Component } from '@angular/core';
import {ActivatedRouteSnapshot, RouterStateSnapshot} from '@angular/router';

@Component({
    selector: 'ovpn-notfound',
    templateUrl: './notfound.component.html'
})
export class NotfoundPageComponent {
    trucs = ['Hello', 'World'];
    constructor(
      public readonly route: ActivatedRouteSnapshot,
      public readonly state: RouterStateSnapshot,
    ) {
    }
}
