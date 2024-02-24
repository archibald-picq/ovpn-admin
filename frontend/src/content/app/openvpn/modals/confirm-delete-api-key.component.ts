import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import {ApiKey} from "../models/openvpn-config.model";
import {ApiKeyService} from '../services/api-key.service';

export class DeleteApiKeyOptions {
    constructor(public readonly apiKey: ApiKey) {
    }
}

@Component({
    selector: 'bus-openvpn-confirm-api-key-account',
    templateUrl: './confirm-delete-api-key.component.html',
    styleUrls: ['./confirm-delete-api-key.component.scss'],
})
export class ConfirmDeleteApiKeyComponent {
    constructor(
        private readonly apiKeyService: ApiKeyService,
        public readonly modal: NgbActiveModal,
        public readonly options: DeleteApiKeyOptions,
    ) {

    }

    public async save(): Promise<void> {
        try {
            await this.apiKeyService.deleteApiKey(this.options.apiKey.id);
            this.modal.close('Save click');
        } catch (e) {
            console.warn('service call failed');
        }
    }
}
