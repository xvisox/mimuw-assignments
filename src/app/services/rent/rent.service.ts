import {Injectable} from '@angular/core';
import {HttpClient, HttpHeaders} from "@angular/common/http";

const API_URL = 'http://localhost:8080/api/rental';

const httpOptions = {
  headers: new HttpHeaders({'Content-Type': 'application/json'})
};

@Injectable({
  providedIn: 'root'
})
export class RentService {

  constructor(private http: HttpClient) {
  }

  rentCar(username: string, carId: number, startDate: string, endDate: string) {
    return this.http.post(API_URL + '/rent', {
      username,
      carId,
      startDate,
      endDate
    });
  }

  extendRental(username: string, carId: number, days: number) {
    return this.http.patch(API_URL + '/extend/' + carId + '/days/' + days, httpOptions);
  }

  returnCar(username: string, carId: number) {
    return this.http.delete(API_URL + '/return/' + carId, httpOptions);
  }
}
