import {Component} from "@angular/core";
import {Router} from "@angular/router";
import {Title} from "@angular/platform-browser";
import {VERSION} from "../../app.constants"

@Component({
    selector: 'ovpn',
    templateUrl: './main.component.html',
    styleUrls: ['./main.component.scss'],
})
export class MainComponent {
  public appVersion = VERSION;
    constructor(
        private readonly router: Router,
        private readonly titleService: Title,
        // private readonly resizeService: ResizeService,
    ) {}
}
