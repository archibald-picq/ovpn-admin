import { NgbTimeStruct, NgbDateStruct } from '@ng-bootstrap/ng-bootstrap';

export interface NgbDateTimeStruct extends NgbDateStruct, NgbTimeStruct { }


export class DateTimeModel implements NgbDateTimeStruct {

  public constructor(
    public year: number,
    public month: number,
    public day: number,
    public hour: number,
    public minute: number,
    public second: number,
    public timeZoneOffset: number | undefined,
  ) {
    // this.year = init.year;
    // this.month = init.month;
    // this.day = init.day;
    // this.hour = init.hour;
    // this.minute = init.minute;
    // this.second = init.second;
    // this.timeZoneOffset = init.timeZoneOffset;
  }

  public static fromLocalString(dateString: string): DateTimeModel | undefined {
    const date = new Date(dateString);

    const isValidDate = !isNaN(date.valueOf());

    if (!dateString || !isValidDate) {
      return undefined;
    }

    return DateTimeModel.fromDate(date);
  }

  public static fromDate(date: Date): DateTimeModel {
    return new DateTimeModel(
      date.getFullYear(),
      date.getMonth() + 1,
      date.getDate(),
      date.getHours(),
      date.getMinutes(),
      date.getSeconds(),
      date.getTimezoneOffset(),
    );
  }

  private static isInteger(value: any): value is number {
    return typeof value === 'number' && isFinite(value) && Math.floor(value) === value;
  }

  public toString(): string {
    if (DateTimeModel.isInteger(this.year) && DateTimeModel.isInteger(this.month) && DateTimeModel.isInteger(this.day)) {
      const year = this.year.toString().padStart(2, '0');
      const month = this.month.toString().padStart(2, '0');
      const day = this.day.toString().padStart(2, '0');

      if (!this.hour) {
        this.hour = 0;
      }
      if (!this.minute) {
        this.minute = 0;
      }
      if (!this.second) {
        this.second = 0;
      }
      if (!this.timeZoneOffset) {
        this.timeZoneOffset = new Date().getTimezoneOffset();
      }

      const hour = this.hour.toString().padStart(2, '0');
      const minute = this.minute.toString().padStart(2, '0');
      const second = this.second.toString().padStart(2, '0');

      const tzo = -this.timeZoneOffset;
      const dif = tzo >= 0 ? '+' : '-',
        pad = function(num: number) {
          const norm = Math.floor(Math.abs(num));
          return (norm < 10 ? '0' : '') + norm;
        };

      const isoString = `${year}-${month}-${day}T${hour}:${minute}:${second}${dif}${pad(tzo / 60)}:${pad(tzo % 60)}`;
      return isoString;
    }

    return '';
  }
}

