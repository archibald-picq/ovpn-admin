import { Component } from '@angular/core';

@Component({
    selector: 'bus-openvpn-upload',
    templateUrl: './upload.component.html',
    styleUrls: ['./upload.component.scss'],
})
export class UploadPageComponent {
    public loading = false;
    public acceptMimeType = '.req,application/pkcs10';

    constructor() {
    }

    public save() {

    }

    public processFile(file: any) {
        console.warn('file selected', file);
    }

    // public processDroppedFile(file: any) {
    //     console.warn('file dropped', file);
    // }
}
