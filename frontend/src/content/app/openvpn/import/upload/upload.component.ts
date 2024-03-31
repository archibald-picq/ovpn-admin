import {Component} from '@angular/core';
import { parse } from 'csv-parse/browser/esm';
import {ActivatedRoute, Router} from '@angular/router';
import {CreateCertificateBatchInfo} from '../model/create-certificate-batch-info.model';

@Component({
  selector: 'bus-import-upload',
  templateUrl: './upload.component.html',
  styleUrls: ['./upload.component.scss'],
})
export class ImportUploadComponent {
  public loading = false;
  public acceptMimeType = 'text/csv';
  public error?: string = undefined;

  constructor(
    private readonly router: Router,
    private readonly route: ActivatedRoute,
  ) {
  }

  public async processFile(files: FileList): Promise<void> {
    try {
      console.warn('file selected', files);
      const content = await this.readFile(files[0]);
      // console.warn('content', content);

      const certs: CreateCertificateBatchInfo[] = await this.parseCsvToObject(content);
      console.warn('certs', certs);
      await this.router.navigate(['./create'], {
        state: {
          importedCertificates: certs,
        },
        relativeTo: this.route,
      });
    } catch (e) {
      this.error = JSON.stringify(e);
    }
  }

  private async readFile(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        // this 'text' is the content of the file
        const text = reader.result;
        if (typeof text !== 'string') {
          console.warn('cant parse file', text);
          reject({message: 'Cant parse file'});
        } else {
          // console.warn('text', text);
          resolve(text);
        }
      }
      reader.onerror = reject;
      reader.readAsText(file);
    })
  }

  private async parseCsvToObject(content: string): Promise<CreateCertificateBatchInfo[]> {
    const tpl = new CreateCertificateBatchInfo();
    const keys = Object.keys(tpl);
    // console.warn('expect keys', keys);
    const rows: string[][] = await this.parseCsv(content);
    // console.warn('read rows', rows);

    const mapping: Map<string, number> = this.findMapping(keys, rows[0]);
    // console.warn('mapping', mapping);
    const certs = rows.slice(1).map(row => {
      const obj = new CreateCertificateBatchInfo();
      mapping.forEach((col, prop) => {
        if (col !== -1) {
          (obj as any)[prop] = row[col];
        }
      });
      return obj;
    });
    // console.warn('certs', certs);

    return certs;
  }

  private async parseCsv(content: string): Promise<string[][]> {
    return new Promise(resolve => {
      const parser = parse({
        delimiter: ','
      });
      const table: string[][] = [];
      parser.on('readable', function(){
        let record;
        while ((record = parser.read()) !== null) {
          table.push(record);
        }
      });
  // Catch any error
      parser.on('error', function(err){
        console.error(err.message);
      });
  // Test that the parsed records matched the expected records
      parser.on('end', function(){
        resolve(table);
        // assert.deepStrictEqual(
        //   records,
        //   [
        //     [ 'root','x','0','0','root','/root','/bin/bash' ],
        //     [ 'someone','x','1022','1022','','/home/someone','/bin/bash' ]
        //   ]
        // );
      });
      parser.write(content);
      parser.end();
      // const lines = content.split(/\r?\n/g);
      // console.warn('lines', lines);
      // return table;
    });
  }

  private findMapping(keys: string[], head: string[]): Map<string, number> {
    const mapping: Map<string, number> = new Map<string, number>();
    keys.forEach(key => {
      const tries = [
        // key is 'commonName'
        key,
        // try 'CommonName'
        key.charAt(0).toUpperCase()+key.substring(1),
        // try 'common_name'
        key.replace(/([A-Z])/, (matches) => '_'+matches.toLowerCase()).toLowerCase(),
        // try 'common_name'
        key.replace(/([A-Z])/, (matches) => '_'+matches.toLowerCase()).toLowerCase().replace('_', ' '),
        // try 'Common Name'
        key.replace(/([A-Z])/, (matches) => '_'+matches.toLowerCase()).replace('_', ' ').split(' ').map(s => s.charAt(0).toUpperCase()+s.substring(1)).join(' '),
      ];
      // console.warn('for', key, 'try', tries);

      const columnIndex = head.findIndex(columnName => tries.findIndex(t => t === columnName) !== -1);
      mapping.set(key, columnIndex);
      // mapping.set(key, tries.find(key)head.findIndex(columnNames => {
      //   console.warn('search', columnNames, 'across', tries);
      //   return tries.indexOf(columnNames)
      // }));
    });

    return mapping;
  }
}
