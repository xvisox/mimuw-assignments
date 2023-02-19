import {Injectable} from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {Observable} from "rxjs";

const API_URL = 'http://localhost:8080/api/';

@Injectable({
  providedIn: 'root'
})
export class OfferService {

  constructor(private http: HttpClient) {
  }

  public getCars(): Observable<any> {
    return this.http.get(API_URL + 'offer');
  }
}
