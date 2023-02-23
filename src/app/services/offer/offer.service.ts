import {Injectable} from '@angular/core';
import {HttpClient, HttpHeaders} from "@angular/common/http";
import {Observable} from "rxjs";
import {StorageService} from "../storage/storage.service";

const API_URL = 'http://localhost:8080/api/offer';

const httpOptions = {
  headers: new HttpHeaders({'Content-Type': 'application/json'})
};

@Injectable({
  providedIn: 'root'
})
export class OfferService {

  constructor(private http: HttpClient, private storage: StorageService) {
  }

  public getCars(): Observable<any> {
    return this.http.get(API_URL);
  }

  public getMyCars(): Observable<any> {
    const username = this.storage.getUser().username;
    return this.http.post(API_URL + '/my',
      {username}, httpOptions
    );
  }
}
