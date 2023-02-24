import {Injectable} from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {Observable} from "rxjs";

const USER_KEY = 'auth-user';
const ALERT_KEY = 'alert-message'
const API_URL = 'http://localhost:8080/api/profile';

@Injectable({
  providedIn: 'root'
})
export class StorageService {
  constructor(private http: HttpClient) {
  }

  clean(): void {
    window.sessionStorage.clear();
  }

  public saveUser(user: any): void {
    window.sessionStorage.removeItem(USER_KEY);
    window.sessionStorage.setItem(USER_KEY, JSON.stringify(user));
  }

  public getUser(): any {
    const user = window.sessionStorage.getItem(USER_KEY);
    if (user) {
      return JSON.parse(user);
    }
    return {};
  }

  public isLoggedIn(): boolean {
    const user = window.sessionStorage.getItem(USER_KEY);
    return !!user;
  }

  public getUserProfile(): Observable<any> {
    return this.http.get(API_URL);
  }

  public removeAlertMessage(): void {
    window.sessionStorage.removeItem('alert-message');
  }

  public saveAlertMessage(message: string): void {
    window.sessionStorage.setItem('alert-message', message);
  }

  public getAlertMessage(): string {
    const message = window.sessionStorage.getItem('alert-message');
    if (message) {
      return message;
    }
    return '';
  }

  public isAlertMessage(): boolean {
    const message = window.sessionStorage.getItem('alert-message');
    return !!message;
  }
}
