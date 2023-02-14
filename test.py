

Skip to content
Using cyber-itus.com Mail with screen readers


import jwt
import json
import datetime
import mimetypes
import logging
import requests

from django.shortcuts import render
from django.http import JsonResponse
from django.views import View
from django.middleware import csrf
from django.conf import settings

from . import validate_payload, authenicate, validate_put_form, validate_delete_form
from . import api, forms

api = api.API()

logger = logging.getLogger(__name__)

_response_failed = {
    'error': True, 'msg': 'Request Failed, Try Again / Contact Support!'
}

def remove_empty_keys(data):
    if type(data) == dict:
        new = dict()
        for each in data.keys():
            if data[each] == '':
                pass
            else:
                new[each] = data[each]
        return new
    return data


class GenericView(View):
    api_name = ''
    urlparams = []
    form_class = ''
    get_form_name = False
    use_uid = True
    add_user = False
    use_user_id = True
    admin_url = False

    def _set_params(self, kwargs):
        params = dict()
        if self.use_uid:
            params.update({'uid': self.uid})
        if self.use_user_id:
            params.update({'u_id': self.u_id})
            params.update({'user_id': self.u_id})
        if self.urlparams:
            for item in self.urlparams:
                params.update({item: kwargs[item]})
        if self.add_user:
            if self.admin:
                params.update({'user_id': 'admin'})
            else:
                params.update({'user_id': kwargs['user_id']})
        return params

    @authenicate
    def get(self, request, *args, **kwargs):
        params = self._set_params(kwargs)
        resp = getattr(api, self.api_name)(url_params=params)
        if resp.status_code == 200:
            resp = resp.json()
        else:
            resp = _response_failed
        return JsonResponse(resp)

    @authenicate
    @validate_payload
    def post(self, request, *args, **kwargs):
        params = self._set_params(kwargs)
        resp = getattr(api, self.api_name)(
            url_params=params, payload=self.payload)
        if resp.status_code == 200:
            resp = resp.json()
        else:
            resp = _response_failed
        return JsonResponse(resp)

    @authenicate
    @validate_put_form
    def put(self, request, *args, **kwargs):
        params = self._set_params(kwargs)
        resp = getattr(api, self.api_name)(
            url_params=params, payload=self.payload)
        if resp.status_code == 200:
            resp = resp.json()
        else:
            resp = _response_failed
        return JsonResponse(resp)

    @authenicate
    @validate_delete_form
    def delete(self, request, *args, **kwargs):
        params = self._set_params(kwargs)
        resp = getattr(api, self.api_name)(
            url_params=params, payload=self.payload)
        if resp.status_code == 200:
            resp = resp.json()
        else:
            resp = _response_failed
        return JsonResponse(resp)


class UploadView(View):
    api_name = ''
    api_delete = ''
    urlparams = []
    delparams = []
    form_class = ''
    file_details = None
    use_uid = True
    use_doc_id = False
    use_user_id = True
    admin_url = False

    def _set_params(self, kwargs):
        params = dict()
        if self.use_uid:
            params.update({'uid': self.uid})
        if self.use_user_id:
            params.update({'u_id': self.u_id})
            params.update({'user_id': self.u_id})
        if self.urlparams:
            for item in self.urlparams:
                params.update({item: kwargs[item]})
        return params

    def _set_delete_params(self, kwargs, payload, resp):
        params = dict()
        if self.use_uid:
            params.update({'uid': self.uid})
        if self.use_doc_id:
            params.update({'doc_id': resp['docid']})
        return params

    @authenicate
    def get(self, request, *args, **kwargs):
        return JsonResponse({'error': False, 'csrf': csrf.get_token(request)})

    @authenicate
    def post(self, request, *args, **kwargs):
        params = self._set_params(kwargs)
        form_data = request.POST.copy()
        # if 'groups' in form_data:
        #     groups = json.loads(form_data['groups'])
        #     del form_data['groups']
        #     form_data['groups'] = groups
        form = getattr(forms, self.form_class)(form_data, request.FILES)
        if form.is_valid():
            data = form.cleaned_data
            file = request.FILES['file']
            del data['file']
            payload = remove_empty_keys(data)
            if self.file_details:
                for each in self.file_details:
                    payload[each] = str(getattr(file, self.file_details[each]))
            if 'content_type' in payload:
                if payload['content_type'] == "":
                    payload['content_type'] = mimetypes.MimeTypes().guess_type(str(file))[
                        0]
            if 'group_acls' in payload:
                payload['group_acls'] = json.loads(payload['group_acls'])
            resp = getattr(api, self.api_name)(
                url_params=params, payload=payload)
            if resp.status_code == 200:
                if resp.json()['error']:
                    resp = {'error': True, 'msg': resp.json()['msg']}
                else:
                    upload_resp = getattr(api, 'upload_file')(url_params={'url': resp.json()[
                        'data']['signed_url']}, payload={'file_obj': file})
                    if upload_resp.status_code == 200:
                        resp = {'error': False,
                                'msg': 'File uploaded successfully!'}
                    else:
                        up = self._set_delete_params(
                            kwargs, payload, resp.json()['data'])
                        doc_del = getattr(api, self.api_delete)(url_params=up)
                        if doc_del.status_code != 200:
                            pass
                        resp = {'error': True,
                                'msg': 'Error uploading, Please try again'}
            else:
                resp = {'error': True, 'msg': 'Error uploading, Please try again'}
        else:
            ejson = json.loads(form.errors.as_json())
            msg = dict([(key, val[0]['message'])
                        for key, val in ejson.items()])
            resp = {'error': True, 'msg': {'errors': msg}}
        return JsonResponse(resp)


class UploadVersionedDocView(View):
    api_name = ''
    api_delete = ''
    form_class = ''
    action = ''
    urlparams = []
    uploadparams = []
    delparams = []
    file_details = None
    use_uid = True
    use_doc_id = False
    use_user_id = True
    admin_url = False

    def _set_params(self, kwargs):
        params = dict()
        if self.use_uid:
            params.update({'uid': self.uid})
        if self.use_user_id:
            params.update({'u_id': self.u_id})
            params.update({'user_id': self.u_id})
        if self.urlparams:
            for item in self.urlparams:
                params.update({item: kwargs[item]})
        return params

    def _set_upload_params(self, resp):
        params = dict()
        if self.use_uid:
            params.update({'uid': self.uid})
        if self.uploadparams:
            for item in self.uploadparams:
                params.update({item: resp[item]})
        signed_url = resp['signed_url']
        return params, signed_url

    def _set_delete_params(self, kwargs, payload, resp):
        pass

    def get(self, request, *args, **kwargs):
        pass

    @authenicate
    def post(self, request, *args, **kwargs):
        params = self._set_params(kwargs)
        form = getattr(forms, self.form_class)(request.POST, request.FILES)
        if form.is_valid():
            data = form.cleaned_data
            file = request.FILES['file']
            del data['file']
            payload = remove_empty_keys(data)
            if self.action == 'UploadVersion':
                payload = {}
                payload['action'] = 'UploadVersion'
            else:
                if self.file_details:
                    for each in self.file_details:
                        payload[each] = str(
                            getattr(file, self.file_details[each]))
            resp = getattr(api, self.api_name)(
                url_params=params, payload=payload)
            if resp.status_code == 200:
                # upload_params, signed_url = self._set_upload_params(resp.json()['data'])
                if resp.json()['error']:
                    return JsonResponse(resp.json())
                upload_resp = getattr(api, 'upload_file')(
                    url_params={'url': resp.json()['url']}, payload={'file_obj': file})
                if upload_resp.status_code == 200:
                    upload_payload = {}
                    versionid = upload_resp.headers['x-amz-version-id']
                    upload_payload['action'] = "AddVersion"
                    upload_payload['s3version'] = versionid
                    if self.action == 'UploadVersion':
                        upload_payload['notes'] = data['notes']
                    else:
                        upload_payload['notes'] = data['description']
                        params['doc_id'] = resp.json()['docid']
                    resp = getattr(api, 'update_versioned_docs')(
                        url_params=params, payload=upload_payload)
                    if resp.status_code == 200:
                        resp = resp.json()
                    else:
                        resp = _response_failed
                else:
                    resp = {'error': True,
                            'msg': 'Error uploading, Please try again'}
            else:
                resp = {'error': True, 'msg': 'Error uploading, Please try again'}
        else:
            ejson = json.loads(form.errors.as_json())
            msg = dict([(key, val[0]['message'])
                        for key, val in ejson.items()])
            resp = {'error': True, 'msg': {'errors': msg}}
        return JsonResponse(resp)


class UploadWatermarkView(View):
    api_name = ''
    next_api_name = ''
    urlparams = []
    form_class = ''
    file_details = None
    use_uid = True
    use_user_id = True
    admin_url = False
    action = ''

    def _set_params(self, kwargs):
        params = dict()
        if self.use_uid:
            params.update({'uid': self.uid})
        if self.use_user_id:
            params.update({'u_id': self.u_id})
            params.update({'user_id': self.u_id})
        if self.urlparams:
            for item in self.urlparams:
                params.update({item: kwargs[item]})
        return params

    @authenicate
    def get(self, request, *args, **kwargs):
        return JsonResponse({'error': False, 'csrf': csrf.get_token(request)})

    @authenicate
    def post(self, request, *args, **kwargs):
        params = self._set_params(kwargs)
        form_data = request.POST.copy()
        form = getattr(forms, self.form_class)(form_data)
        # if watermark, add FILES to validation
        if self.action == 'watermark':
            form = getattr(forms, self.form_class)(form_data, request.FILES)
        if self.action == 'delpages':
            form = getattr(forms, self.form_class)(json.loads(request.body))
        if form.is_valid():
            data = form.cleaned_data
            logger.critical(data)
            # store file in a variable, applicable for watermark
            if 'file' in data:
                fileobj = data['file']
                del data['file']
            response = getattr(api, self.api_name)(url_params=params,payload=data)
            if response.status_code == 200:
                resp_json = response.json()
                logger.critical(resp_json)
                if resp_json['error']:
                    resp = {'error': True, 'msg': 'Error uploading, Please try again'}
                else:
                    data = resp_json['data']
                    p_params = {'u_id': params['u_id'],
                                 'uid': params['uid'],
                                 'new_docid': data['new_docid'],
                                 'old_docid': data['old_docid']}
                    # if watermark, just upload watermark file
                    if self.action == 'watermark':
                        watermark_upload_resp = getattr(api, 'upload_file')(
                                url_params={'url': data['url']},
                                payload={'file_obj': fileobj})
                        if watermark_upload_resp.status_code == 200:
                            watermark_run_resp = getattr(api, self.next_api_name)(url_params=p_params)
                            resp = {'error': False, 'new_docid':data['new_docid'], 'msg': 'Process started.'}
                    if self.action == 'paginate':
                        paginate_run_resp = getattr(api, self.next_api_name)(url_params=p_params)
                        logger.critical(paginate_run_resp)
                        resp = {'error': False, 'new_docid':data['new_docid'], 'msg': 'Process started.'}
                    if self.action == 'shortext':
                        logger.critical(data)
                        shortext_run_resp = getattr(api, self.next_api_name)(url_params=p_params)
                        logger.critical(shortext_run_resp)
                        resp = {'error': False, 'new_docid':data['new_docid'], 'msg': 'Process started.'}
                    if self.action == 'delpages':
                        logger.critical(data)
                        delpages_run_resp = getattr(api, self.next_api_name)(url_params=p_params)
                        logger.critical(delpages_run_resp)
                        resp = {'error': False, 'new_docid':data['new_docid'], 'msg': 'Process started.'}
            else:
                resp = {'error': True, 'msg': 'Error uploading, Please try again'}
        else:
            ejson = json.loads(form.errors.as_json())
            msg = dict([(key, val[0]['message']) for key, val in ejson.items()])
            resp = {'error': True, 'msg': msg}
        return JsonResponse(resp)


class TokenRefreshView(View):

    def put(self, request, *args, **kwargs):
        try:
            payload = json.loads(request.body)
            token = payload.get('token', None)
            if token:
                p = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                p['exp'] = datetime.datetime.utcnow()+datetime.timedelta(seconds=1800)
                token = jwt.encode(p, settings.SECRET_KEY, algorithm='HS256')
                return JsonResponse({'error': False, 'token': token.decode(), 'msg': 'New Token'})
            return JsonResponse({'error': True, 'msg': 'Invalid token'})
        except Exception:
            return JsonResponse({'error': True, 'msg': 'Invalid payload'})


class LoginView(View):
    api_name = ''
    form_class = ''

    def _get_url(self, kwargs):
        return self.api_name

    def get(self, request, *args, **kwargs):
        return JsonResponse({'error': False, 'csrf': csrf.get_token(request)})

    @validate_payload
    def post(self, request, *args, **kwargs):
        api_method = self._get_url(kwargs)
        resp = getattr(api, api_method)(payload=self.payload)
        if resp.status_code == 200:
            if resp.json()['error']:
                return JsonResponse(resp.json())
            else:
                data = resp.json()
                payload = dict()
                req = ['uid', 'admin', 'plan', 'name', 'user_id']
                for each in req:
                    payload[each] = data[each]
                payload['exp'] = datetime.datetime.utcnow(
                )+datetime.timedelta(seconds=1800)
                token = jwt.encode(
                    payload, settings.SECRET_KEY, algorithm='HS256')
                custom_uid = data['custom_uid']
                del data['custom_uid']
                data['uid'] = custom_uid
                return JsonResponse({'error': False, 'token': token.decode(), 'data': data})
        else:
            return JsonResponse({'error': True, 'msg': 'API Temporary Unavailable'})


class ProfessionalView(View):
    api_name = ''
    form_class = ''
    get_form_name = False
    urlparams = []

    def _set_params(self, kwargs):
        params = dict()
        if self.urlparams:
            for item in self.urlparams:
                params.update({item: kwargs[item]})
        return params

    def _get_url(self, kwargs):
        return self.api_name

    def get(self, request, *args, **kwargs):
        params = self._set_params(kwargs)
        resp = getattr(api, self.api_name)(url_params=params)
        if resp.status_code == 200:
            resp = resp.json()
        else:
            resp = _response_failed
        return JsonResponse(resp)

    @validate_payload
    def post(self, request, *args, **kwargs):
        params = self._set_params(kwargs)
        api_method = self._get_url(kwargs)
        resp = getattr(api, api_method)(
            url_params=params, payload=self.payload)
        if resp.status_code == 200:
            if resp.json()['error']:
                return JsonResponse(resp.json())
            else:
                return JsonResponse(resp.json())
        else:
            return JsonResponse({'error': True, 'msg': 'API Temporary Unavailable'})

    @validate_put_form
    def put(self, request, *args, **kwargs):
        params = self._set_params(kwargs)
        self.payload = remove_empty_keys(self.payload)
        resp = getattr(api, self.api_name)(
            url_params=params, payload=self.payload)
        if resp.status_code == 200:
            resp = resp.json()
        else:
            resp = _response_failed
        return JsonResponse(resp)


class InvoiceLogoUploadView(View):
    api_name = ''
    urlparams = []
    use_uid = True
    use_user_id = True
    admin_url = False

    def _set_params(self, kwargs):
        params = dict()
        if self.use_uid:
            params.update({'uid': self.uid})
        if self.use_user_id:
            params.update({'u_id': self.u_id})
            params.update({'user_id': self.u_id})
        if self.urlparams:
            for item in self.urlparams:
                params.update({item: kwargs[item]})
        return params

    @authenicate
    def get(self, request, *args, **kwargs):
        params = self._set_params(kwargs)
        resp = getattr(api, self.api_name)(url_params=params)
        if resp.status_code == 200:
            return JsonResponse({'error': False, 'msg': '', 'data': resp.json()})
        return JsonResponse({'error': True, 'msg': 'Error fetching file', 'data': ''})

    @authenicate
    def post(self, request, *args, **kwargs):
        files = request.FILES
        params = self._set_params(kwargs)
        if 'file' in files:
            fobj = files['file']
            filename = fobj.name
            ftype = mimetypes.MimeTypes().guess_type(filename)[0]
            if not ftype.startswith('image'):
                return JsonResponse({'error': True, 'msg': 'Please upload an image file!'})
            resp = getattr(api, self.api_name)(url_params=params)
            logger.critical(resp.json())
            url = resp.json()['url']
            headers = {'Content-Type': ftype}
            resp = requests.put(url, headers=headers, data=fobj)
        return JsonResponse({'error': False, 'msg': '', 'data': ''})
codecommit.txt
Displaying codecommit.txt.
