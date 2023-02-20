import {Injectable} from '@angular/core';
import {HttpClient, HttpHeaders} from "@angular/common/http";

const API_URL = 'http://localhost:8080/api/offer/rent';

@Injectable({
  providedIn: 'root'
})
export class RentService {

  constructor(private http: HttpClient) {
  }

  rentCar(username: string, carId: number, startDate: string, endDate: string) {
    return this.http.post(API_URL, {
      username,
      carId,
      startDate,
      endDate
    });
  }
}
