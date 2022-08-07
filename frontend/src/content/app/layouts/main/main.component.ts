import {Component} from "@angular/core";
import {Router} from "@angular/router";
import {Title} from "@angular/platform-browser";

@Component({
    selector: 'ovpn',
    templateUrl: './main.component.html'
})
export class MainComponent {
    constructor(
        private readonly router: Router,
        private readonly titleService: Title,
        // private readonly resizeService: ResizeService,
    ) {}
}
