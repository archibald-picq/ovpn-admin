import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import {ApiKey} from '../models/openvpn-config.model';
import {ApiKeyService} from '../services/api-key.service';
import {ApiKeyEditDTO} from '../models/api-key-edit.model';

export class EditApiKeyOptions {
    constructor(public readonly apiKey: ApiKey) {}
}

@Component({
    selector: 'bus-openvpn-api-key-account',
    templateUrl: './edit-api-key.component.html',
    styleUrls: ['./edit-api-key.component.scss'],
})
export class EditApiKeyComponent {
    public tuple: ApiKeyEditDTO = new ApiKeyEditDTO();
    public error = '';
    public loading = false;
    public original?: ApiKey;

    constructor(
        private readonly apiKeyService: ApiKeyService,
        public readonly modal: NgbActiveModal,
        public readonly options: EditApiKeyOptions,
    ) {
        this.original = options?.apiKey;
        this.tuple.comment = options?.apiKey.comment ?? '';
        this.tuple.key = '';
    }

    public async save(): Promise<void> {
        try {
            this.loading = true;
            this.error = '';

            if (this.original) {
                const updated = await this.apiKeyService.updateApiKey(this.original.id, this.tuple);
                this.original.comment = updated.comment;
                this.original.expires = updated.expires;
                this.modal.close(this.original);
            } else {
                const newApiKey = await this.apiKeyService.createApiKey(this.tuple);
                this.modal.close(newApiKey);
            }
        } catch (e: any) {
            this.error = e.error.message;
            console.warn('service call failed: ', e.error.message);
        }
        this.loading = false;
    }
}
